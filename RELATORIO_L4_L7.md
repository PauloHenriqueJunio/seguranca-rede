# Controles L4 e L7 — lab `labfw`

Parte: **experimentos e evidências de L4**, e **proposta pesquisada + experimentos e evidências de L7**.
(L2 e L3 ficam com o parceiro do grupo.)

Topologia (dada pelo professor): LAN A (`pc1` 10.0.1.10, `pc2` 10.0.1.11) — DMZ B (`web` 10.0.2.10, `dns` 10.0.2.11) — Gerência C (`adm` 10.0.3.10) — Borda D (`fw` ↔ `r0` → Internet). Todo o tráfego LAN↔DMZ passa pelo `fw`, que roteia entre `eth0` (LAN), `eth1` (DMZ), `eth2` (Gerência) e `eth3` (WAN).

---

## 1. Como rodar

Tudo roda no Windows, num terminal (PowerShell ou Git Bash), dentro da pasta do lab.

```bash
cd caminho/para/labfw
```

**1. Suba o lab.** No PowerShell/Windows, o `kathara lstart` pode travar com um erro de encoding Unicode (o spinner de progresso usa um caractere que o console do Windows não sabe imprimir). A correção é forçar `TERM=dumb`, que desliga o spinner:

```bash
TERM=dumb kathara lstart
```

Confira que as 7 máquinas subiram:

```bash
TERM=dumb kathara list
```

**2. Rode a bateria de experimentos** (sobe os listeners de teste, aplica cada estado do firewall, roda os testes e salva tudo em `evidencias/`):

```bash
bash experimentos.sh
```

Ele já deixa o `fw` limpo (sem regras) no final. Leva cerca de 1 minuto.

**3. Para aplicar/remover os controles manualmente** (por exemplo, pra testar à mão), entre no `fw`:

```bash
TERM=dumb kathara exec fw -- bash -c "bash /root/l4_p2p.sh"             # aplica L4
TERM=dumb kathara exec fw -- bash -c "bash /root/l4_p2p.sh remover"     # remove L4
TERM=dumb kathara exec fw -- bash -c "bash /root/l7_dpi.sh"             # aplica L7
TERM=dumb kathara exec fw -- bash -c "bash /root/l7_dpi.sh remover"     # remove L7
TERM=dumb kathara exec dns -- bash -c "bash /root/dns_filter.sh"        # aplica filtro de DNS
TERM=dumb kathara exec dns -- bash -c "bash /root/dns_filter.sh remover" # remove filtro de DNS
```

Nota: `kathara exec <maquina> -- bash -c "..."` — o `--` é obrigatório, senão o `kathara exec` tenta interpretar o `-c` como uma opção dele mesmo e dá erro.

Ou entre interativamente com `TERM=dumb kathara connect fw` e rode os comandos direto no shell da máquina.

**4. Derrube o lab** ao terminar:

```bash
TERM=dumb kathara lclean
```

### Estrutura dos arquivos que eu adicionei

| Arquivo | O que é |
|---|---|
| `fw/root/l4_p2p.sh` | Script do professor, corrigido (ver §2) |
| `fw/root/l7_dpi.sh` | Script novo do controle L7 por conteúdo (ver §4) |
| `dns/root/dns_filter.sh` | Script novo do filtro de DNS — domínio e categoria (ver §5) |
| `shared/bt_peer.py` | Simulador de peer BitTorrent (monta o handshake real de 68 bytes), montado em `/shared` em todas as máquinas |
| `experimentos.sh` | Roda a bateria de testes e salva evidências |
| `evidencias/*.txt` | Saída real de cada teste, capturada rodando o lab |

---

## 2. L4 — bloqueio por porta

### Objetivo
Bloquear BitTorrent (peers 6881–6999 TCP/UDP e tracker 6969) no `fw`, olhando só a porta de destino — sem inspecionar o conteúdo do pacote.

### O que o script faz (`fw/root/l4_p2p.sh`)
- Cria uma cadeia própria `P2P` com um `DROP` incondicional, pra manter os contadores desse experimento separados do resto da `FORWARD`.
- Insere 4 regras no **topo** da `FORWARD` (`-I FORWARD 1`), *antes* de qualquer `ACCEPT` — inclusive de conexões já estabelecidas — casando por `-m multiport --dports 6881:6999,6969`, para tcp e udp:
  - `-i eth0` — cliente da LAN abrindo conexão para fora (para um peer/tracker) na porta P2P.
  - `-o eth0` — alguém de fora abrindo conexão **para dentro** da LAN, num host que está servindo BitTorrent na porta P2P.
  - Ao professor, o script original só tinha a direção `-i eth0`; adicionei a `-o eth0` porque um peer da LAN pode estar do lado *servidor* (recebendo conexão), não só do lado cliente.
- **Idempotente**: antes de inserir, roda uma função `remover_regras` que apaga (em loop) todas as cópias de cada regra que já existirem. Rodar `aplicar` duas vezes seguidas não duplica nada, e `remover` sempre limpa tudo — mesmo que tenha rodado várias vezes antes.
- O script original também estava salvo com fim de linha do Windows (CRLF), o que quebra o Bash (`$LAN_IF\r`, `"remover\r"`). Corrigi para LF.

### Experimentos e evidências
Ferramenta de teste: `shared/bt_peer.py`, que monta o handshake **real** do protocolo BitTorrent (68 bytes: `0x13` + `"BitTorrent protocol"` + 8 bytes reservados + info\_hash + peer\_id) — ver `evidencias/E0_baseline.txt`, `E1_l4.txt`.

| Teste | Cenário | Esperado | Observado |
|---|---|---|---|
| E0 | baseline, sem regra, `pc1`→`web:6881` | passa | passou, 68 bytes recebidos no servidor |
| **E1** | L4 ativo, `pc1`(LAN, cliente)→`web:6881` | bloqueado | `TimeoutError: timed out` no `connect()` — nem o handshake TCP fecha |
| **E1b** | L4 ativo, `web`(fora)→`pc1:6881` (LAN **servindo**) | bloqueado | `TimeoutError: timed out` — prova que a regra `-o eth0` funciona |
| **E1c** | L4 ativo, `pc1`→`web:443` (mesmo tráfego BT, porta trocada) | **passa** | conectou e entregou os 68 bytes — **evasão por porta** |

Contadores no `fw` depois do E1 (`iptables -L P2P -v -n`): `8 pkts / 480 bytes` no `DROP` da cadeia `P2P` — batendo com as tentativas de E1 + E1b (a pilha TCP re-tenta o SYN algumas vezes antes de desistir, por isso mais de 2 pacotes).

### Limitações do L4 (evidenciadas no experimento)
- **Evasão trivial por porta**: como mostrado no E1c, o mesmo tráfego BitTorrent na porta 443 passa direto — o L4 não olha o conteúdo.
- Clientes BitTorrent reais usam portas **aleatórias** por padrão (não fixas em 6881–6999), então a lista de portas do script já nasce incompleta fora de laboratório.
- Não cobre **uTP** (BitTorrent sobre UDP com portas dinâmicas), **criptografia de protocolo (MSE/PE)** nem tráfego **DHT** fora da porta 6969.

---

## 3. L7 — proposta pesquisada

Como o L4 é evadido só trocando a porta, a defesa em profundidade pede uma camada que olhe o **conteúdo**, a **aplicação** ou o **destino** (domínio) — não só a porta. Pesquisei 5 tecnologias:

| Tecnologia | Como funciona | Pra que serve melhor | Efeito em TLS/criptografado | Custo / desempenho | Onde entraria na topologia |
|---|---|---|---|---|---|
| **DNS Filtering** (dnsmasq/BIND com lista de domínios) | O servidor DNS recusa resolver (ou resolve pra `0.0.0.0`) nomes de uma lista — de um domínio só ou de uma categoria inteira | Bloquear **domínio específico** e **categoria de site**, antes mesmo de qualquer pacote sair pra internet | Nem chega a importar — a decisão é antes da conexão existir | Muito baixo (é só uma tabela de nomes) | No servidor `dns` da DMZ, ou apontando os clientes pra um resolver com essa lista |
| **DPI por assinatura** (`iptables -m string`, nDPI) | Casa uma sequência de bytes conhecida no payload (ex.: handshake BitTorrent, `GET /admin`) | **Identificar a aplicação independente da porta** e controlar recurso específico (path) dentro dela | **Cega** — não enxerga dentro do TLS | Baixo (é o que já está no `fw`, sem serviço extra) | Inline no `fw`, junto com o L4 |
| **IPS/NGFW inline** (Suricata via NFQUEUE) | Motor de assinaturas + heurísticas (regras ET/Snort) + reconhecimento de app por fingerprint, decide `accept`/`drop` pacote a pacote | Tudo que o DPI faz, só que atualizável e escalável — é a evolução natural de um "Application Firewall" pra um NGFW de verdade | Parcial (server name / fingerprint do handshake TLS, não o conteúdo) | Médio/alto (CPU por pacote) | Inline no `fw`, no lugar do `-m string` |
| **Proxy de aplicação** (Squid + filtro por SNI/CONNECT/categoria) | Toda sessão passa por um proxy explícito ou transparente; decide por domínio/SNI/categoria antes de liberar o túnel | Bloquear **domínio** e **categoria** também, mas já com a conexão TCP estabelecida (mais controle e log por sessão que o DNS Filtering) | Enxerga o SNI (não o payload) em TLS | Médio (mais um salto, mais uma banda) | Entre LAN e DMZ/Internet, como gateway obrigatório |
| **WAF / Application Firewall** (ModSecurity, na frente do `web`) | Regras específicas de aplicação Web (OWASP CRP): path, método, payload malicioso | **Permitir `/public` e bloquear `/admin`**, e outros controles de recurso da própria aplicação | Roda depois do TLS terminar no servidor, então vê o conteúdo | Baixo/médio, só no host protegido | No `web` da DMZ, na frente da aplicação |

### O que cada capacidade pedida pelo professor mapeia

| Capacidade pedida | Tecnologia | Implementei? |
|---|---|---|
| Bloquear um domínio específico | DNS Filtering | ✅ §5 |
| Bloquear categoria de sites | DNS Filtering | ✅ §5 |
| Permitir `/public` e bloquear `/admin` | DPI por assinatura / WAF | ✅ §4 |
| Identificar aplicação independente da porta | DPI por assinatura | ✅ §4 |
| Controlar recurso/conteúdo de uma aplicação | DPI por assinatura / WAF | ✅ §4 |

### Recomendação para este lab
Implementei e testei duas: **DPI por assinatura com `iptables -m string`** (§4) e **DNS Filtering com `dnsmasq`** (§5) — ambas já vêm na imagem do Kathará, não exigem subir serviço extra, e juntas cobrem as 5 capacidades pedidas (tabela acima).

Para um ambiente real, a minha recomendação seria evoluir o DPI pra **Suricata inline** (mesmo princípio, mas com motor de regras atualizável e fingerprint de TLS) e trocar o `dnsmasq` isolado por um **Proxy com lista de categorias** (mais controle e log por sessão do que só DNS) + **WAF no `web`** para proteger a aplicação da DMZ especificamente.

---

## 4. L7 — experimento e evidências

### O que o script faz (`fw/root/l7_dpi.sh`, novo)
Mesmo padrão do `l4_p2p.sh` (idempotente, inserido no topo da `FORWARD`), mas casando pelo **conteúdo** do pacote com `-m string --algo bm`, em **qualquer porta**:

- **Handshake BitTorrent**: `--hex-string "|13|BitTorrent protocol"` (o byte `0x13` não é imprimível, por isso a notação hexadecimal) em TCP, nas duas direções (`-i eth0` / `-o eth0`) → cadeia `L7` → `DROP`.
- **Consulta DHT mainline** (BEP 5): `--string "d1:ad2:id20:"` em UDP, também nas duas direções → mesma cadeia `L7` → `DROP`.
- **Caminho HTTP `/admin`**: `--string "GET /admin"`, só de LAN (`eth0`) para DMZ (`eth1`), porta 80 → cadeia própria `L7HTTP` → **`REJECT --reject-with tcp-reset`** (ao invés de `DROP`), pra deixar claro pro usuário que o acesso foi negado, em vez de simplesmente não responder.

### Experimentos e evidências
`shared/bt_peer.py` também simula uma consulta DHT (`dht <ip> <porta>`) e tem um modo `--plain` (manda texto qualquer, não-BT), pra provar que o bloqueio é por conteúdo e não por porta.

| Teste | Cenário | Esperado | Observado |
|---|---|---|---|
| **E2** | L7 ativo, `pc1`→`web:443` (mesma porta do E1c) | bloqueado pelo conteúdo | TCP conecta (o handshake em si não tem payload), mas o servidor **nunca recebe os 68 bytes**: `"conexao de (...) aceita, mas nenhum dado chegou (timeout)"` |
| E2b | L7 ativo, tráfego **não-BT** `pc1`→`web:443` | passa | servidor recebeu `b'HELLO nao-BT...'` — confirma que o L7 olha o conteúdo, não a porta |
| E2c | L7 ativo, consulta DHT `pc1`→`web:33445/udp` (porta fora do range do L4) | bloqueado pelo conteúdo | contador da regra DHT em `L7` incrementou (`1 pkt`) |
| E2d | L7 ativo, `curl` `pc1`→`web`/public/ e /admin/ | só `/admin/` bloqueado | `GET /public/ → 200` · `GET /admin/ → conexão recusada/resetada` (RST) — o `/public` do enunciado é liberado, o `/admin` é barrado |
| E3 | L4 + L7 juntos | ambos atuando | `web:6881` cai no L4 (timeout no connect), `web:443` passa pelo L4 mas cai no L7 (conecta, sem dado), `/admin/` cai no `L7HTTP` |

Ponto importante, visível nas evidências (`evidencias/E2_l7.txt`, `E3_l4_l7.txt`): como o `-m string` só enxerga o **payload**, e o handshake TCP (SYN/SYN-ACK/ACK) não carrega dado nenhum, a conexão **estabelece** mesmo estando bloqueada — diferente do L4, que já derruba o SYN. A prova do bloqueio, nesse caso, não é "a conexão falhou", e sim **"o servidor nunca recebeu o payload"** — por isso o script de testes confere o log do servidor (`tail /tmp/srv443.log`) além da saída do cliente.

### Limitações do L7 por assinatura (evidenciadas/esperadas)
- **Não enxerga tráfego cifrado**: se o BitTorrent estiver dentro de um túnel TLS/HTTPS de verdade (não só usando a porta 443, mas com handshake TLS real), a assinatura não aparece no payload visível e a regra não casa.
- A assinatura pode ficar **fragmentada entre pacotes** (o handshake cair dividido em dois segmentos TCP), e o `-m string` do Linux só olha pacote a pacote — nesse caso o bloqueio falha.
- **Falso positivo**: qualquer protocolo que por acaso contenha a mesma sequência de bytes é bloqueado também.
- Custo de CPU por pacote (busca de string) é maior que o L4 (só olha cabeçalho), embora nesse volume de tráfego de laboratório isso não apareça.

---

## 5. Bloqueio de domínio e de categoria (DNS Filtering)

### Objetivo
Cobrir os dois itens do enunciado que o DPI por assinatura não resolve: **bloquear um domínio específico** e **bloquear uma categoria inteira de sites** — antes mesmo do pacote sair pra rede.

### Como funciona
Como o lab não tem internet de verdade, inventei uns "sites falsos" só pra testar. O script `dns/root/dns_filter.sh` sobe um `dnsmasq` na máquina `dns` (10.0.2.11) com uma listinha:

| Nome | Categoria | Resposta do DNS |
|---|---|---|
| `loja.exemplo` | — (permitido) | `10.0.2.10` (resolve normal, pro `web`) |
| `filmes-gratis.exemplo` | domínio específico | `0.0.0.0` (bloqueado) |
| `serie-online.exemplo` | categoria "streaming pirata" | `0.0.0.0` (bloqueado) |
| `torrent-facil.exemplo` | categoria "streaming pirata" | `0.0.0.0` (bloqueado) |

Quando o nome está na lista de bloqueio, o DNS responde `0.0.0.0` — o nome nunca vira um IP de verdade, então o navegador (ou qualquer aplicação) nem chega a tentar abrir conexão com lugar nenhum. É o controle "mais barato" que existe: a decisão acontece **antes** de qualquer pacote de dado sair da máquina.

Mesmo padrão dos outros dois scripts: `bash dns_filter.sh` liga o filtro, `bash dns_filter.sh remover` desliga.

### Experimento e evidências
Teste com `dig`, direto no servidor DNS do lab (`evidencias/E4_dns.txt`):

| Teste | Cenário | Esperado | Observado |
|---|---|---|---|
| E4a | `dig @10.0.2.11 loja.exemplo` | permitido, resolve | `10.0.2.10` |
| E4b | `dig @10.0.2.11 filmes-gratis.exemplo` | bloqueado (domínio específico) | `0.0.0.0` |
| E4c | `dig @10.0.2.11 serie-online.exemplo` e `torrent-facil.exemplo` | bloqueados (categoria) | `0.0.0.0` nos dois |

O log do próprio `dnsmasq` (`/tmp/dnsmasq.log` no `dns`) confirma as 4 consultas chegando e mostra a decisão de cada uma: `config loja.exemplo is 10.0.2.10` vs. `config filmes-gratis.exemplo is 0.0.0.0` — ou seja, o mesmo servidor, a mesma consulta, e uma decisão diferente por nome.

### Limitações do DNS Filtering
- Só funciona se o cliente realmente usar **esse** servidor DNS — qualquer app pode ignorar e usar outro resolver (público, ou até fixar o IP direto sem resolver nome nenhum).
- Não enxerga **conteúdo**, só o nome que foi pedido — não serve pra path (`/admin`) nem pra identificar aplicação por assinatura, por isso ele complementa o DPI do §4 em vez de substituir.
- Em produção, mudanças de IP do lado bloqueado não importam (o bloqueio é pelo nome), mas o dono do site pode contornar registrando um nome novo.

---

## 6. L4 + L7 e Defense in Depth

O experimento deixa isso concreto: nenhuma camada sozinha cobre tudo.
- O **L4** é barato e bloqueia de cara qualquer coisa na porta oficial (6881–6999, 6969) — inclusive interrompe conexões já abertas, nas duas direções (cliente ou servidor na LAN).
- Quando o L4 é evadido só trocando a porta (E1c), o **L7 por assinatura** ainda pega, porque olha o conteúdo, não a porta (E2, E2c) — e também controla recurso específico de uma aplicação (`/admin` vs. `/public`, E2d).
- O **DNS Filtering** (§5) cobre o que nenhum dos dois faz: bloquear por **domínio/categoria**, antes mesmo do primeiro pacote sair.
- E cada um tem sua própria limitação (L4: evasão de porta; DPI: tráfego cifrado/fragmentado; DNS: só vale se o cliente usar aquele resolver) — que pediria a próxima camada (proxy/IPS com fingerprint de TLS, ou WAF na aplicação, ver §3).

Cada camada assume que a anterior pode falhar e cobre um ângulo diferente do mesmo problema (porta → conteúdo → aplicação → nome/domínio) — essa é a peça que, junto com a parte L2/L3 do parceiro, forma o Defense in Depth completo do lab.
