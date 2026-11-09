# Firewall IPv4 + IPv6 e endurecimento do roteador (MikroTik hEX, RouterOS 7)
#
# Contexto: a chain "input" estava vazia. Todo SYN que chegava da internet sem conexao
# era respondido pelo proprio roteador com um RST (TTL 64). No "hole punch" do acesso
# remoto, o SYN do outro lado chega alguns ms antes do SYN do PC sair, e esse RST
# matava a conexao direta. De quebra, os servicos do roteador (FTP, SSH, Telnet, WWW, API)
# estavam abertos para a WAN, inclusive por IPv6, e os aparelhos da LAN ficavam
# expostos por IPv6 (o forward IPv6 nao tinha regra de bloqueio).
#
# Como aplicar: Terminal do WinBox com o Safe Mode ligado (Ctrl+X). Se a conexao cair,
# o RouterOS desfaz tudo sozinho. Ajuste os nomes de interface ao seu caso.
# Pressupostos: listas de interface LAN (bridge1) e WAN (ether1 + pppoe-out1).

/interface list
add name=WAN
add name=LAN
/interface list member
add interface=bridge1 list=LAN
add interface=ether1 list=WAN
add interface=pppoe-out1 list=WAN

# --- IPv4: entrada no roteador e encaminhamento (mesma logica da config de fabrica) ---
/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="defconf: accept established,related,untracked"
add chain=input action=drop connection-state=invalid comment="defconf: drop invalid"
add chain=input action=accept protocol=icmp comment="defconf: accept ICMP"
add chain=input action=drop in-interface-list=!LAN comment="defconf: drop all not coming from LAN"
add chain=forward action=fasttrack-connection connection-state=established,related comment="FastTrack"
add chain=forward action=accept connection-state=established,related,untracked comment="defconf: accept established,related,untracked"
add chain=forward action=drop connection-state=invalid comment="defconf: drop invalid"
add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN comment="defconf: drop all from WAN not DSTNATed"

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN

# --- IPv6: sem isto, qualquer aparelho da casa com IPv6 global fica acessivel da internet ---
/ipv6 firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="defconf: accept established,related,untracked"
add chain=input action=drop connection-state=invalid comment="defconf: drop invalid"
add chain=input action=accept protocol=icmpv6 comment="defconf: accept ICMPv6"
add chain=input action=accept protocol=udp dst-port=546 src-address=fe80::/10 comment="defconf: accept DHCPv6-Client prefix delegation"
add chain=input action=drop in-interface-list=!LAN comment="defconf: drop everything else not coming from LAN"
add chain=forward action=fasttrack-connection connection-state=established,related comment="FastTrack IPv6"
add chain=forward action=accept connection-state=established,related,untracked comment="defconf: accept established,related,untracked"
add chain=forward action=drop connection-state=invalid comment="defconf: drop invalid"
add chain=forward action=accept protocol=icmpv6 comment="defconf: accept ICMPv6"
add chain=forward action=drop in-interface-list=!LAN comment="defconf: drop everything else not coming from LAN"

# --- Endurecimento: so a LAN enxerga e administra o roteador ---
/ip neighbor discovery-settings set discover-interface-list=LAN
/tool mac-server set allowed-interface-list=LAN
/tool mac-server mac-winbox set allowed-interface-list=LAN
/tool bandwidth-server set enabled=no
/ip service disable telnet,ftp,www,api,api-ssl,reverse-proxy
# No RouterOS 7.24 o parametro "address" de /ip service virou "available-from".
/ip service set ssh available-from=192.168.88.0/24
/ip service set winbox available-from=192.168.88.0/24

# Hipotese descartada no caminho: "liberal-tcp-tracking=yes" NAO resolveu as quedas
# e foi revertido para o padrao:
/ip firewall connection tracking set liberal-tcp-tracking=no
