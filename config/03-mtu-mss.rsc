# MTU e MSS acompanhando o PPPoE (MikroTik hEX, RouterOS 7)
#
# O PPPoE da operadora negocia MTU 1492. A configuracao herdada estava ajustada para 1480
# (MSS 1440 e anuncio de MTU 1480 no IPv6). Ajustado para o valor real:
#   MSS = 1492 - 20 (IPv4) - 20 (TCP) = 1452
#
# Achado sobre o keepalive do PPPoE: com o keepalive ligado, a sessao subia com MTU 1480;
# com ele desligado, subia com 1492. O plano de dados carrega 1492 de verdade (testado com
# ping sem fragmentacao em IPv4 e IPv6), entao o keepalive ficou desligado de proposito.
# Custo: se a sessao morrer em silencio, o roteador nao percebe sozinho. A sugestao
# (nao aplicada) e um watchdog no Netwatch que derruba e sobe o PPPoE se a internet sumir.

/interface pppoe-client set pppoe-out1 keepalive-timeout=disabled

/ip firewall mangle
add chain=forward action=change-mss new-mss=1452 passthrough=yes protocol=tcp tcp-flags=syn tcp-mss=1453-65535 out-interface=pppoe-out1 comment="clamp MSS PPPoE (saida)"
add chain=forward action=change-mss new-mss=1452 passthrough=yes protocol=tcp tcp-flags=syn tcp-mss=1453-65535 in-interface=pppoe-out1 comment="clamp MSS PPPoE (entrada)"

# Os aparelhos IPv6 da LAN passam a usar 1492 (anunciado no Router Advertisement)
/ipv6 nd set [find default=yes] mtu=1492

# Teste no Windows (sem fragmentar):
#   IPv4: ping -f -l 1464 1.1.1.1      (1464 + 8 ICMP + 20 IP = 1492)
#   IPv6: ping -6 -l 1444 <destino>    (1444 + 8 ICMPv6 + 40 IPv6 = 1492; IPv6 nunca fragmenta no caminho)
# Ver a MTU negociada:
#   /interface pppoe-client monitor pppoe-out1 once
