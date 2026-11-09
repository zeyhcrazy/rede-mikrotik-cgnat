# Usuario so de leitura para diagnostico e auditoria (MikroTik, RouterOS 7)
#
# Todo o diagnostico e a auditoria foram feitos com um usuario que so le:
# entra por SSH com chave, ve configuracao e contadores, roda ping/traceroute,
# mas nao altera nada, nao ve senhas ("!sensitive") e nao captura pacotes ("!sniff").
# As mudancas foram aplicadas depois, pelo dono da rede, uma de cada vez.

/user group
add name=leitura policy="ssh,read,test,!local,!telnet,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!api,!romon,!rest-api"

# Aceito so a partir de um IP da LAN (de preferencia com lease fixo no DHCP).
# Defina uma senha forte para a conta pelo WinBox; o acesso do dia a dia e pela chave.
/user add name=auditoria group=leitura address=192.168.88.10/32

# Chave publica do PC que faz a auditoria (o arquivo .pub e enviado antes pelo Files do WinBox)
/user ssh-keys import user=auditoria public-key-file=auditoria.pub

# Uso a partir do PC (Windows, OpenSSH nativo):
#   ssh -i $env:USERPROFILE\.ssh\mikrotik_leitura auditoria@192.168.88.1 "/export terse"
#   ssh -i $env:USERPROFILE\.ssh\mikrotik_leitura auditoria@192.168.88.1 "/ip firewall connection print count-only"
#
# Dica: scripts longos com :for/:delay costumam ser interrompidos pelo SSH. E mais estavel
# fazer o laco no PC e mandar um comando curto por vez (ver scripts/vigiar-conntrack.ps1).
