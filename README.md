# Rede de casa com MikroTik atrás de CGNAT: firewall, bufferbloat e auditoria

Estudo de caso de administração de rede em um **MikroTik hEX (RB750Gr3, RouterOS 7)** ligado por PPPoE a uma ONT **ZTE F670L**, atrás do **CGNAT** da operadora. São três trabalhos na mesma rede:

1. Descobrir por que as conexões diretas de acesso remoto caíam em segundos. A causa era o firewall.
2. Corrigir o bufferbloat (ping que dispara quando o upload enche) com fila **CAKE**.
3. Fazer uma auditoria só de leitura da configuração e aplicar as correções uma a uma, medindo antes e depois.

> Dados pessoais foram removidos: IP público, MACs, usuário PPPoE, números de série, nomes de aparelhos e IPs de terceiros. Os endereços de exemplo usam as faixas de documentação (`203.0.113.0/24`, `2001:db8::/32`). A rede `192.168.88.0/24` é o padrão de fábrica da MikroTik.

## Topologia

```
                ┌──────────── ONT ZTE F670L ─────────────┐
 fibra ── PON ──┤ LAN1: WAN em bridge (o PPPoE é do hEX) ├── ether1 ──┐
                │ outra LAN + Wi-Fi 2,4 / 5 GHz          ├── ether3 ──┤  MikroTik hEX (RB750Gr3)
                └────────────────────────────────────────┘            │  RouterOS 7.25
                                                         PC ── ether2 ┘  LAN 192.168.88.0/24
```

- **WAN:** PPPoE no hEX. IPv4 dentro do CGNAT (`100.64.0.0/10`, sem IP público) e IPv6 global por DHCPv6 com delegação de prefixo.
- **LAN:** `bridge1` com ether2 (PC) e ether3. A ether3 volta para a ONT, para que o Wi-Fi da ONT receba DHCP do hEX e fique na mesma rede.

## Parte 1: conexão direta caindo (firewall)

### O problema

Sessões de acesso remoto (AnyDesk) conectavam em modo direto e caíam entre 70 ms e 3 s depois que a imagem começava. O resto funcionava: navegação, downloads longos e a conexão de controle do programa, que ficava de pé por horas.

### O diagnóstico

- **Acesso só de leitura.** Criei no roteador um usuário que só lê (`ssh,read,test`, sem `write`, `sensitive` nem `sniff`), aceito só a partir do IP do PC. Ver [`config/05-usuario-leitura.rsc`](config/05-usuario-leitura.rsc).
- **Conntrack ao vivo.** Escrevi um script que, a cada 300 ms, cruza as conexões TCP do processo no PC com a tabela de conntrack do roteador via SSH ([`scripts/vigiar-conntrack.ps1`](scripts/vigiar-conntrack.ps1)). No roteador, a conexão ia para `close`, ou seja, passava um RST.
- **Hipótese descartada.** Testei `liberal-tcp-tracking=yes`, para o caso de o conntrack estar estrito demais. Não resolveu e foi revertido.
- **Captura de pacotes.** Usei o sniffer do RouterOS (só cabeçalhos) na bridge e na PPPoE. O RouterOS 7 grava **pcapng** com uma interface por sentido (`bridge1 rx`, `pppoe-out1 tx` etc.). Escrevi um leitor de pcapng em PowerShell com C# embutido ([`scripts/analisar-pcap.ps1`](scripts/analisar-pcap.ps1)). Ele casa o mesmo segmento TCP dos dois lados do roteador e diz de onde veio cada RST: do PC, da internet ou do próprio roteador. O TTL confirma a origem: 128/127 é o Windows, 64 é o RouterOS.
- **Causa raiz.** Fiz um teste com o outro lado numa rede 4G. No *hole punch*, o SYN do outro lado chegou na WAN **17 ms antes** de o SYN do PC sair. Como a chain `input` estava vazia, o roteador tratou esse SYN como destinado a ele mesmo e respondeu com um **RST próprio (TTL 64)**, o que matava a tentativa de conexão direta.

Na mesma análise apareceram mais três problemas:

- Os serviços do roteador (FTP, SSH, Telnet, WWW e API) estavam abertos para a WAN, inclusive por IPv6.
- O `forward` do IPv6 não tinha bloqueio, então os aparelhos da casa com IPv6 global ficavam acessíveis da internet.
- Os SYN do PC saíam pela PPPoE com MSS 1460, sem ajuste para a MTU menor do PPPoE.

### A correção

Em [`config/01-firewall.rsc`](config/01-firewall.rsc):

- Firewall IPv4 e IPv6 no padrão da configuração de fábrica da MikroTik (`input` e `forward`).
- Serviços sem uso desligados. SSH e WinBox aceitos só da LAN.
- Descoberta de vizinhos e MAC server limitados à LAN, e servidor de *bandwidth test* desligado.
- Ajuste de MSS na PPPoE (o valor final está em [`config/03-mtu-mss.rsc`](config/03-mtu-mss.rsc)).

Tudo foi aplicado com o **Safe Mode** do WinBox ligado. Se o acesso cair, o RouterOS desfaz sozinho.

### O resultado

- A conexão direta passou a fechar em menos de 1 s.
- Uma sessão real ficou estável até ser encerrada pelo usuário.
- Numa série de desconexões e reconexões forçadas, nenhuma caiu sozinha. O conntrack só mostrou `close` nos encerramentos manuais.
- Os serviços do roteador e os aparelhos com IPv6 deixaram de aceitar conexões novas vindas da WAN.

## Parte 2: bufferbloat (CAKE no upload)

### O problema

Com o upload cheio, o ping subia e perdia pacotes, o que atrapalhava jogos e chamadas. O paliativo que existia era um limite por hardware na porta do switch (ingress 950M / egress 400M). Isso é um *policer*: ele descarta pacotes quando passa do limite, sem fila inteligente e sem justiça entre os fluxos.

### Como medi

[`scripts/medir.ps1`](scripts/medir.ps1) roda o Speedtest CLI e, ao mesmo tempo, pinga o roteador, `1.1.1.1` e `8.8.8.8` a cada 200 ms. Cada ping é marcado com a fase do teste (repouso, carga ou após). O script gera um CSV com todos os pings e um resumo com média, p95, máximo e perdas por fase. Para comparar configurações, usei sempre o mesmo servidor e o IPv4. Também usei o teste de bufferbloat da Waveform no navegador.

### Resultados

| Configuração | Download | Upload | Latência no upload (IQM / pico) | Ping 1.1.1.1 durante o teste (média / p95 / máx) | Pings perdidos |
|---|---|---|---|---|---|
| Sem nenhum limite | 928 Mbps | 435 Mbps | 50,8 / 68 ms | 48 / 129 / 390 ms | 18 de 53 |
| Limite na porta do switch | 839 Mbps | 382 Mbps | 10,1 / 222 ms | 14,5 / 23 / 27 ms | 2 de 47 |
| **CAKE no upload a 200M** | 814 Mbps | 195 Mbps | **1,4 / 4 ms** | **13,8 / 19 / 23 ms** | **0 de 74** |

Em repouso, o ping para `1.1.1.1` fica em ~12 ms. Sem limite, ele quadruplica durante o teste e um terço dos pacotes se perde. Com o CAKE, a latência sob carga fica praticamente igual à de repouso. A troca é consciente: o upload cai de ~435 para ~195 Mbps em troca de latência estável. No teste da Waveform, a configuração final tirou **A+ / A / A** em três execuções. Os números completos estão em [`resultados/medicoes.csv`](resultados/medicoes.csv).

### A correção

Em [`config/02-cake-upload.rsc`](config/02-cake-upload.rsc):

- Uma **queue tree na interface PPPoE** com CAKE. Queue tree com *parent* na interface continua valendo com o **FastTrack** ligado. O FastTrack só pula simple queues e queue trees globais.
- `cake-flowmode=dual-srchost`, para dividir o upload de forma justa entre os aparelhos da casa.
- `cake-nat=yes`. Sem ele, todo o IPv4 sai com o mesmo IP depois do NAT, e o CAKE não consegue separar os aparelhos.
- Limite de 200M. Com o upload saturado, o CAKE usa 40–65% de cada núcleo do hEX, o que deixa folga para o resto.

### Limites do hEX (por que não há CAKE no download)

- Só o PPPoE no download a ~850 Mbps já ocupa um núcleo do hEX a 97–98%. No IPv6 a 860–880 Mbps, a carga chega a 99–100%. Uma fila de download derrubaria a velocidade.
- O hEX usa um SoC MT7621 com uma única IRQ para toda a Ethernet, e o RouterOS 7.25 não tem RPS para essa plataforma. Conferi no terminal: não há como espalhar mais a carga.
- **Testei e desfiz** um *policer* de entrada na porta da WAN (ether1). A 950M nada mudou. A 850M ficou pior: o download caiu para 783 Mbps e a latência no download foi de ~7 para 33 ms, porque o *policer* também descarta os pacotes de ping e de jogo.
- Todas as execuções mostraram um pico de ~210–250 ms no início do download, com ou sem limite. Isso indica rajada do lado da operadora, não do roteador.
- Conclusão: controlar a fila no download exige um roteador com CPU mais forte. Na ONT também não dá: o QoS nativo dela só oferece prioridade 802.1p e limite de banda por aparelho, sem gerência ativa de fila (AQM).

## Parte 3: auditoria só de leitura

Li a configuração e os contadores com o usuário só de leitura, sem alterar nada. As propostas foram para um `.rsc` com blocos independentes. Antes das mudanças, um backup. Depois, cada bloco foi aplicado separadamente, com o OK do dono da rede.

| Achado | O que foi feito | Resultado |
|---|---|---|
| RouterBOOT (firmware de boot) em 7.14.3 com RouterOS 7.25 | `/system routerboard upgrade` e reboot (48 s sem internet) | Firmware de boot em 7.25 |
| PPPoE negociando MTU 1492, mas MSS ajustado para 1440 e IPv6 anunciando MTU 1480 | MSS 1452 e MTU 1492 no anúncio IPv6 ([`03-mtu-mss.rsc`](config/03-mtu-mss.rsc)) | Ping sem fragmentar de 1492 bytes passa em IPv4 e IPv6 |
| Com o *keepalive* do PPPoE ligado, a sessão subia com MTU 1480 | *Keepalive* mantido desligado de propósito. Sugerido um watchdog no Netwatch (não aplicado) | MTU 1492 preservada |
| DNS primário da operadora lento (média de 165 ms, picos de 813 ms) | Cache DNS no hEX, com o servidor rápido da operadora na frente, e o DHCP entregando o roteador como DNS ([`04-dns-cache.rsc`](config/04-dns-cache.rsc)) | Consulta fora do cache: mediana de 136 para **6,4 ms**. Em cache: ~1,2 ms |
| `cake-nat` desligado | Ligado | Justiça por aparelho também no IPv4 |
| Restos de configuração: filas desativadas, pool de DHCP sem uso, cliente DHCP desativado na WAN, rota desativada, membros de lista apontando para interfaces que não existem mais | Removidos. Os backups antigos no flash ficaram para o dono decidir | Configuração exportada limpa |
| Cliente NTP desligado; `tcp-syncookies` e `rp-filter` no padrão | Propostos, não aplicados | Pendente |
| ether1 e ether3 na mesma camada 2 dentro da ONT: o hEX enxerga na porta da LAN o MAC da própria WAN e o do concentrador PPPoE da operadora | Documentado. Nenhum efeito prático observado até agora | Pendente |

Com o conjunto de mudanças, a latência no download IPv6 caiu de **14,0 para 7,9 ms** (IQM), e o download IPv4 foi de 794 para 816 Mbps. Na checagem final: test-ipv6 com 10/10, 1500 pings em 60 s de repouso sem nenhuma perda e jitter abaixo de 0,6 ms, e nenhum erro no log depois do reboot.

No Wi-Fi da ONT, a varredura de vizinhos mostrou 17 redes em 2,4 GHz. Fixei o canal 1 com 20 MHz, o menos disputado entre os fortes, e o 5 GHz no canal 157 com 80 MHz, o bloco 149–161 mais limpo fora dos canais DFS.

## O que fica de lição

- **Medir antes e depois, com o mesmo servidor e uma mudança por vez.** O *policer* de entrada parecia uma boa ideia e piorou o resultado.
- **O sniffer do RouterOS desliga o FastTrack no hEX.** Com ele rodando, a internet cai para ~125 Mbps. Pare a captura logo em seguida.
- **Firewall vazio não é só um risco de segurança.** Aqui ele também quebrava funcionalidade: o próprio roteador respondia com RST e matava as conexões diretas.
- **Nome de parâmetro muda entre versões.** No RouterOS 7.24, o `address` de `/ip service` virou `available-from`.

## Estrutura

| Arquivo | O que tem |
|---|---|
| [`config/01-firewall.rsc`](config/01-firewall.rsc) | Firewall IPv4/IPv6 e endurecimento do roteador |
| [`config/02-cake-upload.rsc`](config/02-cake-upload.rsc) | Fila CAKE no upload (queue tree na PPPoE) |
| [`config/03-mtu-mss.rsc`](config/03-mtu-mss.rsc) | MSS 1452, MTU 1492 no IPv6 e o achado do *keepalive* |
| [`config/04-dns-cache.rsc`](config/04-dns-cache.rsc) | Cache DNS no roteador |
| [`config/05-usuario-leitura.rsc`](config/05-usuario-leitura.rsc) | Grupo e usuário só de leitura para diagnóstico |
| [`scripts/medir.ps1`](scripts/medir.ps1) | Velocidade + pings em paralelo por fase (bufferbloat) |
| [`scripts/analisar-pcap.ps1`](scripts/analisar-pcap.ps1) | Leitor de pcap/pcapng que classifica a origem de cada RST |
| [`scripts/vigiar-conntrack.ps1`](scripts/vigiar-conntrack.ps1) | Cruza as conexões do PC com o conntrack do roteador |
| [`resultados/medicoes.csv`](resultados/medicoes.csv) | Resumo de todas as medições citadas |

Os `.rsc` são trechos que ilustram cada solução, não um backup completo. Ajuste os nomes de interface antes de usar e aplique com o Safe Mode ligado.

## Licença

[MIT](LICENSE).
