# Cache DNS no roteador (MikroTik hEX, RouterOS 7)
#
# Achado da auditoria: o DNS primario entregue pela operadora respondia devagar
# (media de 165 ms, picos de 813 ms), enquanto outro servidor da mesma operadora
# respondia em ~3 ms. O PC usava o primario lento.
#
# Solucao: o roteador vira o DNS da casa (com cache), com o servidor rapido na frente.
# Os servidores dinamicos do PPPoE continuam como reserva.
# Seguro de ligar porque a regra "drop all not coming from LAN" (01-firewall.rsc)
# ja bloqueia DNS vindo da WAN; sem ela, isto viraria um resolvedor aberto.
#
# 203.0.113.53 e 2001:db8::53 sao enderecos de documentacao: use os do seu provedor.

/ip dns set allow-remote-requests=yes servers=203.0.113.53,2001:db8::53

# O DHCP passa a entregar o roteador como DNS (no PC: ipconfig /renew)
/ip dhcp-server network set [find address="192.168.88.0/24"] dns-server=192.168.88.1

# Resultado medido: consulta "fria" (fora do cache) de mediana 136 ms para 6,4 ms;
# consulta em cache em ~1,2 ms. O RouterOS nao guarda resposta NODATA (ex.: dominio sem
# AAAA), entao essas sempre vao ao servidor (~4,6 ms).
#
# Para desfazer:
# /ip dns set allow-remote-requests=no servers=""
# /ip dhcp-server network set [find address="192.168.88.0/24"] dns-server=""
