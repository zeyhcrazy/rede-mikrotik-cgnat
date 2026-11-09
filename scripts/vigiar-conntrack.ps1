param(
    [string]$Processo = 'AnyDesk',
    [string]$Roteador = '192.168.88.1',
    [string]$Usuario = 'auditoria',                                   # usuario so de leitura (config/05-usuario-leitura.rsc)
    [string]$Chave = "$env:USERPROFILE\.ssh\mikrotik_leitura",
    [int]$MaxMinutes = 15,
    [int]$QuietSeconds = 25
)
# Vigia as conexoes TCP de um processo no PC e, ao mesmo tempo, o conntrack do roteador
# para os mesmos IPs remotos (via SSH com o usuario so de leitura). Serve para ver em que
# momento a conexao vira "close" no roteador e quem fechou.
# Sai sozinho quando uma sessao nova aparece e some por $QuietSeconds, ou apos $MaxMinutes.
$ssh = "$env:SystemRoot\System32\OpenSSH\ssh.exe"
$out = Join-Path $PSScriptRoot 'vigia-conntrack.txt'
function Get-Conns {
    $pids = @(Get-Process $Processo -ErrorAction SilentlyContinue | ForEach-Object Id)
    if (-not $pids.Count) { return @() }
    @(Get-NetTCPConnection -OwningProcess $pids -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|::$)' -and $_.State -ne 'Listen' })
}
function Log($m) { $l = "$(Get-Date -Format HH:mm:ss.fff) $m"; Add-Content $out $l; $l }
Set-Content $out "start $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
# Conexoes que ja existiam (ex.: a conexao de controle com o servidor do programa) ficam de fora.
$baseIps = @{}
foreach ($c in Get-Conns) { $baseIps[$c.RemoteAddress] = 1; Log "base $($c.LocalAddress):$($c.LocalPort) > $($c.RemoteAddress):$($c.RemotePort) $($c.State)" | Out-Null }
$prev = @{}
$recent = @{}   # peer -> ultima vez visto no PC; o roteador continua sendo consultado 20 s depois para pegar o close/RST
$seen = $false; $lastAlive = $null
$end = (Get-Date).AddMinutes($MaxMinutes)
while ((Get-Date) -lt $end) {
    $now = @{}
    foreach ($c in Get-Conns) { $now["$($c.LocalPort)>$($c.RemoteAddress):$($c.RemotePort)"] = $c }
    foreach ($key in $now.Keys) {
        $c = $now[$key]
        if (-not $prev.ContainsKey($key)) { Log "NEW  $($c.LocalAddress):$($c.LocalPort) > $($c.RemoteAddress):$($c.RemotePort) $($c.State) pid=$($c.OwningProcess)" }
        elseif ($prev[$key].State -ne $c.State) { Log "STATE $key $($prev[$key].State) -> $($c.State)" }
    }
    foreach ($key in $prev.Keys) { if (-not $now.ContainsKey($key)) { Log "GONE $key (era $($prev[$key].State))" } }
    $prev = $now
    $pcPeers = @($now.Values | Where-Object { -not $baseIps.ContainsKey($_.RemoteAddress) } | ForEach-Object RemoteAddress | Sort-Object -Unique)
    foreach ($p in $pcPeers) { $recent[$p] = Get-Date }
    $peers = @($recent.Keys | Where-Object { ((Get-Date) - $recent[$_]).TotalSeconds -lt 20 })
    if ($pcPeers.Count) { $seen = $true; $lastAlive = Get-Date }
    if ($peers.Count) {
        # Um comando curto por vez: lacos longos dentro do RouterOS sao interrompidos pelo SSH.
        # No PowerShell 5.1 as aspas dentro do argumento do ssh precisam ir como \".
        $cond = ($peers | ForEach-Object { "src-address~\`"$_\`" or dst-address~\`"$_\`"" }) -join ' or '
        $rb = ":foreach c in=[/ip firewall connection find where protocol=tcp and ($cond)] do={ :do { :put ([/ip firewall connection get `$c src-address] . \`":\`" . [/ip firewall connection get `$c src-port] . \`" > \`" . [/ip firewall connection get `$c dst-address] . \`":\`" . [/ip firewall connection get `$c dst-port] . \`" \`" . [/ip firewall connection get `$c tcp-state] . \`" fasttrack=\`" . [/ip firewall connection get `$c fasttrack] . \`" to=\`" . [/ip firewall connection get `$c timeout]) } on-error={} }"
        foreach ($l in (& $ssh -i $Chave -o BatchMode=yes -o ConnectTimeout=3 "$Usuario@$Roteador" $rb 2>&1)) { if ("$l".Trim()) { Log "RB $l" | Out-Null } }
    }
    if (-not $pcPeers.Count -and $seen -and ((Get-Date) - $lastAlive).TotalSeconds -ge $QuietSeconds) {
        Log "sessao encerrada ha $QuietSeconds s - saindo"; break
    }
    Start-Sleep -Milliseconds 300
}
Log "end"
