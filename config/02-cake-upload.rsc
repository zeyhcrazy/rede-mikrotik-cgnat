# Fila CAKE no upload, contra o bufferbloat (MikroTik hEX, RouterOS 7)
#
# Antes: limite por hardware na porta do switch (ingress 950M / egress 400M na ether1).
# Isso e um "policer": corta pacotes quando passa do limite, sem fila inteligente e sem
# justica entre fluxos. O ping continuava disparando com o upload cheio.
#
# Agora: CAKE so no sentido de saida, numa queue tree pendurada na interface PPPoE.
# - Queue tree com parent na interface continua valendo com o FastTrack ligado
#   (o FastTrack pula simple queue e queue tree "global", nao a de interface).
# - dual-srchost: divide o upload de forma justa entre os aparelhos da casa.
# - cake-nat=yes: o CAKE consulta o conntrack para ver o IP de antes do NAT. Sem isso,
#   todo o IPv4 sai com o mesmo IP e a justica por aparelho nao funciona.
# - 200M: troca upload bruto (~435 Mbps sem limite) por latencia (IQM de ~50 ms para ~1,5 ms).
#   Com o upload saturado, o CAKE usa 40-65% de cada nucleo do hEX, sobrando folga.
#
# Download: NAO tem CAKE de proposito. So o PPPoE a ~850 Mbps ja ocupa quase toda a CPU do
# hEX; uma fila de download derrubaria a velocidade (ver README, "Limites do hEX").

/queue type
add name=cake-upload kind=cake cake-flowmode=dual-srchost cake-nat=yes

/queue tree
add name=upload-cake parent=pppoe-out1 packet-mark=no-mark max-limit=200M queue=cake-upload

# Conferir se a fila esta trabalhando (contadores de bytes, drops e fila):
# /queue tree print stats where name="upload-cake"
