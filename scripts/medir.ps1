<#
.SYNOPSIS
  Mede velocidade e bufferbloat: roda o Speedtest CLI e, ao mesmo tempo, pinga o roteador e
  dois destinos na internet, marcando cada ping com a fase (repouso / carga / apos).

.DESCRIPTION
  Gera, na pasta de saida:
    <Nome>.json          resultado bruto do Speedtest (latencia IQM e pico em download e upload)
    <Nome>-pings.csv     cada ping: hora, destino, fase, status, ms
    <Nome>-resumo.json   resumo: velocidades + media, p95, maximo e perdidos por destino e fase
  Use sempre o mesmo servidor (-Servidor) para comparar antes e depois de uma mudanca.
  O Speedtest CLI (Ookla) nao vem junto: baixe em speedtest.net/apps/cli.

.EXAMPLE
  .\medir.ps1 -Nome antes-cake -Servidor 12345 -IPv4
  .\medir.ps1 -Nome depois-cake -Servidor 12345 -IPv4
#>
param(
    [Parameter(Mandatory = $true)][string]$Nome,
    [int]$Servidor = 0,                       # 0 = o Speedtest escolhe
    [switch]$IPv4,                            # forca IPv4 (usa o IP local da rota padrao)
    [string]$TestHost = '',
    [string]$Gateway = '192.168.88.1',
    [string]$Speedtest = (Join-Path $PSScriptRoot 'speedtest.exe'),
    [string]$Saida = (Join-Path $PSScriptRoot 'medicoes')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Speedtest)) { throw "Speedtest CLI nao encontrado em $Speedtest" }
New-Item -ItemType Directory -Force -Path $Saida | Out-Null
$marker = Join-Path $Saida ($Nome + '-fase.txt')
$stop = Join-Path $Saida ($Nome + '-fim.txt')
if (Test-Path -LiteralPath $stop) { throw 'Use um nome novo para preservar as medicoes anteriores.' }
Set-Content -LiteralPath $marker -Value 'repouso'

# Um job por destino, pingando a cada 200 ms ate o arquivo de fim aparecer.
$jobs = foreach ($destino in @($Gateway, '1.1.1.1', '8.8.8.8')) {
    Start-Job -ArgumentList $destino, $marker, $stop -ScriptBlock {
        param($destino, $marker, $stop)
        $ping = [System.Net.NetworkInformation.Ping]::new()
        try {
            while (-not (Test-Path -LiteralPath $stop)) {
                $fase = (Get-Content -LiteralPath $marker -Raw).Trim()
                $ts = [DateTimeOffset]::Now.ToString('o')
                try {
                    $r = $ping.Send($destino, 900)
                    [pscustomobject]@{ Data = $ts; Destino = $destino; Fase = $fase; Status = [string]$r.Status; Ms = if ($r.Status -eq 'Success') { $r.RoundtripTime } else { $null } }
                } catch { [pscustomobject]@{ Data = $ts; Destino = $destino; Fase = $fase; Status = 'Error'; Ms = $null } }
                Start-Sleep -Milliseconds 200
            }
        } finally { $ping.Dispose() }
    }
}
$exitCode = 1
try {
    Start-Sleep -Seconds 7
    Set-Content -LiteralPath $marker -Value 'carga'
    $speedArgs = @('--accept-license', '--accept-gdpr', '--format=json', '--progress=no')
    if ($TestHost) { $speedArgs += "--host=$TestHost" } elseif ($Servidor) { $speedArgs += "--server-id=$Servidor" }
    if ($IPv4) {
        $ipLocal = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4Address.IPAddress
        if (-not $ipLocal) { throw 'Nao achei o IPv4 local da rota padrao.' }
        $speedArgs += "--ip=$ipLocal"
    }
    # No PowerShell 5.1, redirecionar o stderr de um .exe com ErrorActionPreference=Stop
    # vira erro na primeira linha (o Speedtest escreve um aviso de licenca no stderr).
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        & $Speedtest @speedArgs 2> (Join-Path $Saida ($Nome + '-erro.txt')) | Set-Content -LiteralPath (Join-Path $Saida ($Nome + '.json')) -Encoding utf8
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $eap }
    Set-Content -LiteralPath $marker -Value 'apos'
    Start-Sleep -Seconds 3
} finally {
    Set-Content -LiteralPath $stop -Value 'fim'
    $rows = @($jobs | Wait-Job | Receive-Job)
    $jobs | Remove-Job
    $rows | Select-Object Data, Destino, Fase, Status, Ms | Export-Csv -LiteralPath (Join-Path $Saida ($Nome + '-pings.csv')) -NoTypeInformation -Encoding utf8
}
if ($exitCode -ne 0) { throw "Speedtest falhou ($exitCode); veja $Nome-erro.txt." }

$j = Get-Content -LiteralPath (Join-Path $Saida ($Nome + '.json')) -Raw | ConvertFrom-Json
$summary = [ordered]@{
    Nome = $Nome; Servidor = $j.server.id
    DownloadMbps = [math]::Round($j.download.bandwidth * 8 / 1e6, 2); UploadMbps = [math]::Round($j.upload.bandwidth * 8 / 1e6, 2)
    PingMs = $j.ping.latency
    DownloadPingMs = $j.download.latency.iqm; DownloadPicoMs = $j.download.latency.high
    UploadPingMs = $j.upload.latency.iqm; UploadPicoMs = $j.upload.latency.high
    Perda = $j.packetLoss; Pings = @()
}
foreach ($g in ($rows | Group-Object Destino, Fase)) {
    $ok = @($g.Group | Where-Object Status -eq 'Success' | Sort-Object { [double]$_.Ms })
    $summary.Pings += [pscustomobject]@{
        Destino = $g.Group[0].Destino; Fase = $g.Group[0].Fase; Amostras = $g.Count; Perdidos = $g.Count - $ok.Count
        MediaMs = if ($ok.Count) { [math]::Round(($ok | Measure-Object Ms -Average).Average, 2) } else { $null }
        P95Ms = if ($ok.Count) { $ok[[math]::Max(0, [math]::Ceiling($ok.Count * .95) - 1)].Ms } else { $null }
        MaxMs = if ($ok.Count) { $ok[-1].Ms } else { $null }
    }
}
$summary | ConvertTo-Json -Depth 8 | Tee-Object -FilePath (Join-Path $Saida ($Nome + '-resumo.json'))
