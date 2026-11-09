param([string]$Path, [string[]]$Peer = @(), [int]$Context = 6, [int]$MaxRst = 60)
# Leitor de pcap/pcapng (RouterOS 7 grava pcapng com "bridge1 rx/tx", "pppoe-out1 rx/tx").
# Mostra: pacotes por interface, cada RST com a ORIGEM (PC, internet ou a propria RB),
# vazamentos sem NAT, MSS dos SYN e ICMP (frag-needed/unreachable).
# A origem sai casando o mesmo segmento TCP (IP:porta remota + seq) nos dois lados da RB.
# O TTL confirma: 128/127 = Windows (direto / depois de 1 salto), 64 = gerado pelo RouterOS.
# Captura no roteador (so cabecalhos, em RAM; baixe o arquivo pelo Files do WinBox):
#   /tool sniffer set only-headers=yes filter-interface=bridge1,pppoe-out1 file-name=captura.pcap
#   /tool sniffer start   ...   /tool sniffer stop
# Cuidado: com o sniffer rodando o hEX desliga o FastTrack e a internet cai para ~125 Mbps.
# Pare o sniffer logo depois da captura.
# Uso: .\analisar-pcap.ps1 -Path .\captura.pcap [-Peer 203.0.113.10]
# -Peer: limita a analise aos IPs informados (ex.: -Peer 203.0.113.10).
# Formato curto da interface: LAN> = veio do PC/LAN (bridge rx), LAN< = RB mandou pra LAN,
# WAN> = RB mandou pra internet (pppoe tx), WAN< = chegou da internet (pppoe rx).
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.IO; using System.Net;
public class Pkt {
    public int N; public double T; public int If; public string Src = "", Dst = ""; public int Sp, Dp, Proto;
    public string Flags = ""; public int Len, Pay, Win, Ttl, Mss = -1, IcmpType = -1, IcmpCode = -1, IcmpMtu = -1;
    public uint Seq, Ack; public string Inner = "";
}
public static class PcapReader {
    static int BE16(byte[] b, int o) { return b[o] << 8 | b[o + 1]; }
    static uint BE32(byte[] b, int o) { return (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]); }
    static string V4(byte[] b, int o) { return b[o] + "." + b[o + 1] + "." + b[o + 2] + "." + b[o + 3]; }
    static string V6(byte[] b, int o) { var a = new byte[16]; Array.Copy(b, o, a, 0, 16); return new IPAddress(a).ToString(); }
    public static List<Pkt> Read(string path, List<string> ifNames) {
        var b = File.ReadAllBytes(path); var list = new List<Pkt>(); var links = new List<int>(); var res = new List<double>();
        uint magic = BitConverter.ToUInt32(b, 0); int n = 0;
        if (magic == 0x0A0D0D0A) {
            int o = 0;
            while (o + 12 <= b.Length) {
                uint t = BitConverter.ToUInt32(b, o); int l = (int)BitConverter.ToUInt32(b, o + 4);
                if (l < 12 || o + l > b.Length) break;
                if (t == 1) {
                    links.Add(BitConverter.ToUInt16(b, o + 8)); string name = "if" + ifNames.Count; double r = 1e-6;
                    int p = o + 16;
                    while (p + 4 <= o + l - 4) {
                        int c = BitConverter.ToUInt16(b, p), ln = BitConverter.ToUInt16(b, p + 2);
                        if (c == 0) break;
                        if (c == 2) name = System.Text.Encoding.UTF8.GetString(b, p + 4, ln).TrimEnd('\0');
                        if (c == 9) { int v = b[p + 4]; r = (v & 0x80) != 0 ? Math.Pow(2, -(v & 0x7f)) : Math.Pow(10, -v); }
                        p += 4 + ((ln + 3) & ~3);
                    }
                    ifNames.Add(name); res.Add(r);
                } else if (t == 6) {
                    int iface = (int)BitConverter.ToUInt32(b, o + 8);
                    ulong ts = ((ulong)BitConverter.ToUInt32(b, o + 12) << 32) | BitConverter.ToUInt32(b, o + 16);
                    int cap = (int)BitConverter.ToUInt32(b, o + 20);
                    n++; var k = Parse(b, o + 28, cap, links[iface]);
                    if (k != null) { k.N = n; k.T = ts * res[iface]; k.If = iface; list.Add(k); }
                }
                o += l;
            }
        } else {
            bool le = magic == 0xa1b2c3d4 || magic == 0xa1b23c4d; bool ns = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
            Func<int, uint> U = (x) => le ? BitConverter.ToUInt32(b, x) : BE32(b, x);
            int link = (int)U(20); ifNames.Add("if0"); int o = 24;
            while (o + 16 <= b.Length) {
                double ts = U(o) + U(o + 4) / (ns ? 1e9 : 1e6); int cap = (int)U(o + 8); int p = o + 16; o = p + cap; n++;
                if (o > b.Length) break;
                var k = Parse(b, p, cap, link);
                if (k != null) { k.N = n; k.T = ts; k.If = 0; list.Add(k); }
            }
        }
        return list;
    }
    static Pkt Parse(byte[] b, int p, int cap, int link) {
        int end = p + cap, ip = -1;
        if (link == 1) {
            if (cap < 14) return null;
            int et = BE16(b, p + 12), q = p + 14;
            while ((et == 0x8100 || et == 0x88a8) && q + 4 <= end) { et = BE16(b, q + 2); q += 4; }
            if (et == 0x8864 && q + 8 <= end) { int pp = BE16(b, q + 6); et = pp == 0x0021 ? 0x0800 : pp == 0x0057 ? 0x86dd : 0; q += 8; }
            if (et == 0x0800 || et == 0x86dd) ip = q;
        } else if (link == 113) { if (cap >= 16) ip = p + 16; }
        else ip = p;
        if (ip < 0 || ip >= end) return null;
        var k = new Pkt(); int l4; int ver = b[ip] >> 4;
        if (ver == 4) {
            if (ip + 20 > end) return null;
            int ihl = (b[ip] & 15) * 4; k.Len = BE16(b, ip + 2); k.Ttl = b[ip + 8]; k.Proto = b[ip + 9];
            k.Src = V4(b, ip + 12); k.Dst = V4(b, ip + 16); l4 = ip + ihl; k.Pay = k.Len - ihl;
        } else if (ver == 6) {
            if (ip + 40 > end) return null;
            k.Len = BE16(b, ip + 4) + 40; k.Proto = b[ip + 6]; k.Ttl = b[ip + 7];
            k.Src = V6(b, ip + 8); k.Dst = V6(b, ip + 24); l4 = ip + 40; k.Pay = k.Len - 40;
        } else return null;
        if (k.Proto == 6 && l4 + 20 <= end) {
            k.Sp = BE16(b, l4); k.Dp = BE16(b, l4 + 2); k.Seq = BE32(b, l4 + 4); k.Ack = BE32(b, l4 + 8);
            int doff = (b[l4 + 12] >> 4) * 4; int fl = b[l4 + 13]; k.Win = BE16(b, l4 + 14); k.Pay -= doff;
            string f = ""; if ((fl & 2) != 0) f += "S"; if ((fl & 16) != 0) f += "A"; if ((fl & 1) != 0) f += "F"; if ((fl & 4) != 0) f += "R"; if ((fl & 8) != 0) f += "P"; k.Flags = f;
            if ((fl & 2) != 0) { int q = l4 + 20; while (q < l4 + doff && q < end) { int kind = b[q]; if (kind == 0) break; if (kind == 1) { q++; continue; } if (q + 1 >= end) break; int ol = b[q + 1]; if (kind == 2 && q + 3 < end) k.Mss = BE16(b, q + 2); if (ol < 2) break; q += ol; } }
        } else if (k.Proto == 17 && l4 + 8 <= end) { k.Sp = BE16(b, l4); k.Dp = BE16(b, l4 + 2); k.Pay -= 8; }
        else if ((k.Proto == 1 || k.Proto == 58) && l4 + 8 <= end) {
            k.IcmpType = b[l4]; k.IcmpCode = b[l4 + 1]; k.IcmpMtu = BE16(b, l4 + 6);
            int ii = l4 + 8;
            if (k.Proto == 1 && ii + 20 <= end && (b[ii] >> 4) == 4) { int ih = (b[ii] & 15) * 4; string s = V4(b, ii + 12) + ">" + V4(b, ii + 16) + " proto=" + b[ii + 9]; if (ii + ih + 4 <= end) s += " ports=" + BE16(b, ii + ih) + ">" + BE16(b, ii + ih + 2); k.Inner = s; }
        }
        return k;
    }
}
'@
$ifNames = New-Object 'System.Collections.Generic.List[string]'
$pk = [PcapReader]::Read((Resolve-Path $Path).Path, $ifNames)
function Short([int]$i) {
    $n = $ifNames[$i]
    if ($n -match '^(bridge|ether2)') { if ($n -match 'rx') { 'LAN>' } else { 'LAN<' } }
    elseif ($n -match '^(pppoe|ether1)') { if ($n -match 'tx') { 'WAN>' } else { 'WAN<' } }
    else { $n }
}
$short = @{}; for ($i = 0; $i -lt $ifNames.Count; $i++) { $short[$i] = Short $i }
"arquivo: $Path  pacotes IP: $($pk.Count)  interfaces: $(($ifNames | ForEach-Object { "$_=$($short[$ifNames.IndexOf($_)])" }) -join ', ')"
$Peer = @($Peer | ForEach-Object { $_ -split "," } | Where-Object { $_ })   # -File passa "a,b" como texto unico
if ($Peer.Count) {
    $set = @{}; foreach ($p in $Peer) { $set[$p] = 1 }
    $rx = ($Peer | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $pk = @($pk | Where-Object { $set.ContainsKey($_.Src) -or $set.ContainsKey($_.Dst) -or ($_.Inner -and $_.Inner -match $rx) })
    "filtrado para peer(s) $($Peer -join ', '): $($pk.Count) pacotes"
}
if (-not $pk.Count) { return }
$tz = [TimeZoneInfo]::Local
function Clock([double]$t) { [TimeZoneInfo]::ConvertTimeFromUtc([DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds($t), $tz).ToString('HH:mm:ss.fff') }
function Show($x) {
    $pr = switch ($x.Proto) { 6 { 'tcp' } 17 { 'udp' } 1 { 'icmp' } 58 { 'icmp6' } default { "p$($x.Proto)" } }
    $s = if ($x.Sp) { "$($x.Src):$($x.Sp)" } else { $x.Src }; $d = if ($x.Dp) { "$($x.Dst):$($x.Dp)" } else { $x.Dst }
    $extra = if ($x.Proto -eq 6) { "{0,-4} pay={1,-5} win={2,-5} seq={3} ack={4}" -f $x.Flags, $x.Pay, $x.Win, $x.Seq, $x.Ack } elseif ($x.IcmpType -ge 0) { "type=$($x.IcmpType) code=$($x.IcmpCode) mtu=$($x.IcmpMtu) [$($x.Inner)]" } else { "pay=$($x.Pay)" }
    if ($x.Mss -ge 0) { $extra += " mss=$($x.Mss)" }
    '{0,7} {1} {2} {3,-5} {4,-26} > {5,-26} len={6,-5} ttl={7,-3} {8}' -f $x.N, (Clock $x.T), $short[$x.If], $pr, $s, $d, $x.Len, $x.Ttl, $extra
}
"== pacotes por interface"
$pk | Group-Object If | ForEach-Object { '{0,-16} {1}' -f $ifNames[[int]$_.Name], $_.Count }

# Origem de cada RST: casa o mesmo segmento (IP:porta remota + seq) do outro lado da RB.
function IsLocal([string]$ip) { $ip -match '^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)' }
$byKey = @{}
foreach ($x in $pk) {
    if ($x.Proto -ne 6) { continue }
    $toRemote = (IsLocal $x.Src) -and -not (IsLocal $x.Dst)
    $remote = if ($toRemote) { "$($x.Dst):$($x.Dp)" } else { "$($x.Src):$($x.Sp)" }
    $key = "$remote|$toRemote|$($x.Seq)|$($x.Flags)"
    if (-not $byKey.ContainsKey($key)) { $byKey[$key] = New-Object System.Collections.Generic.List[object] }
    $byKey[$key].Add($x)
}
$rsts = @($pk | Where-Object { $_.Proto -eq 6 -and $_.Flags -match 'R' })
"== RSTs: $($rsts.Count) (mostrando ate $MaxRst)"
$origin = @{}
$shown = 0
foreach ($r in $rsts) {
    $toRemote = (IsLocal $r.Src) -and -not (IsLocal $r.Dst)
    $remote = if ($toRemote) { "$($r.Dst):$($r.Dp)" } else { "$($r.Src):$($r.Sp)" }
    $mates = @($byKey["$remote|$toRemote|$($r.Seq)|$($r.Flags)"] | Where-Object { $_ -ne $r -and [Math]::Abs($_.T - $r.T) -lt 1 })
    $sides = @($mates | ForEach-Object { $short[$_.If] }) + $short[$r.If]
    $o = if ($sides -contains 'LAN>' -and $sides -contains 'WAN>') { 'PC mandou, RB repassou pra internet' }
         elseif ($sides -contains 'WAN<' -and $sides -contains 'LAN<') { 'veio da INTERNET, RB repassou pro PC' }
         elseif ($sides -contains 'LAN>') { 'PC mandou, RB NAO repassou' }
         elseif ($sides -contains 'WAN<') { 'veio da internet, RB absorveu' }
         elseif ($sides -contains 'WAN>') { 'GERADO PELA RB -> internet' }
         elseif ($sides -contains 'LAN<') { 'GERADO PELA RB -> PC/LAN' }
         else { '?' }
    # O sniffer da bridge1 perde parte do IPv6 (todos os SYN, p.ex.), entao IPv6 sem par nao prova nada.
    if ($r.Src -match ':' -and $mates.Count -eq 0) { $o = 'IPv6 sem par (captura da bridge incompleta, origem incerta)' }
    if ($mates.Count -and $mates[0].T -lt $r.T) { continue }   # ja contado pelo primeiro lado
    $origin[$o] = 1 + [int]$origin[$o]
    if ($shown -lt $MaxRst) { $shown++; "-- [$o]"; Show $r; foreach ($m in $mates) { Show $m } }
}
"== resumo da origem dos RSTs"
$origin.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { '{0,5}  {1}' -f $_.Value, $_.Key }

"== contexto antes de cada RST que nao veio do PC (ate 10)"
$i = 0
foreach ($r in $rsts | Where-Object { $short[$_.If] -ne 'LAN>' } | Select-Object -First 10) {
    $flow = @($pk | Where-Object { $_.Proto -eq 6 -and (($_.Sp -eq $r.Sp -and $_.Dp -eq $r.Dp) -or ($_.Sp -eq $r.Dp -and $_.Dp -eq $r.Sp)) -and $_.T -le $r.T + 0.2 -and $_.T -ge $r.T - 5 })
    "-- RST #$($r.N)"; $flow | Select-Object -Last ($Context + 3) | ForEach-Object { Show $_ }
}
"== vazamentos sem NAT (WAN> com origem privada da LAN)"
$leak = @($pk | Where-Object { $short[$_.If] -eq 'WAN>' -and $_.Src -match '^192\.168\.' })
"$($leak.Count) pacotes"; $leak | Select-Object -First 15 | ForEach-Object { Show $_ }
"== MSS anunciado nos SYN (por lado)"
$pk | Where-Object { $_.Mss -ge 0 } | Group-Object { "$($short[$_.If]) $($_.Flags) mss=$($_.Mss)" } | Sort-Object Count -Descending | ForEach-Object { '{0,6}  {1}' -f $_.Count, $_.Name }
"== ICMP de erro (unreachable / frag-needed / time-exceeded / too-big)"
$icmp = @($pk | Where-Object { ($_.Proto -eq 1 -and $_.IcmpType -in 3, 11, 12) -or ($_.Proto -eq 58 -and $_.IcmpType -in 1, 2, 3) })
"$($icmp.Count) pacotes"; $icmp | Select-Object -First 30 | ForEach-Object { Show $_ }
"== maiores pacotes por interface"
$pk | Group-Object If | ForEach-Object { '{0,-16} maxlen={1}' -f $ifNames[[int]$_.Name], ($_.Group | Measure-Object Len -Maximum).Maximum }
