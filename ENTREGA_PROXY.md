# Forward Proxy (Squid) e Reverse Proxy (NGINX)

Evolução do lab anterior: dois nós novos, `proxy` (Squid, na LAN) e `rp` (NGINX, na DMZ) — uma segunda camada de controle, independente do firewall (Defense in Depth). Detalhamento completo em `RELATORIO_PROXY.md`; aqui só as evidências objetivas e o SRL.

## 1. Como rodar

```bash
docker build -t kathara-proxy .        # uma vez (imagem com nginx + squid)
TERM=dumb kathara lstart               # sobe o lab (fw, proxy, rp, pc1, pc2, web, dns, adm, r0)
bash experimentos_proxy.sh             # roda a bateria P0-P7 e grava evidencias/P*.txt (~2 min)
TERM=dumb kathara lclean               # derruba o lab
```

```bash
bash /root/fw_proxy.sh antes     # Task anterior: Internet -> web direto
bash /root/fw_proxy.sh depois    # Task atual: Internet -> rp -> web; saída só pelo Squid
bash /root/fw_proxy.sh remover   # volta a FORWARD ACCEPT
```

## 2. Topologia

4 zonas no `fw` (eth0-eth3): **LAN** 10.0.1.0/24 (`pc1` .10, `pc2` .11, `proxy`/Squid .12:3128), **DMZ** 10.0.2.0/24 (`web` .10:80, `dns` .11, `rp`/NGINX .12:80), **Gerência** 10.0.3.0/24 (`adm` .10) e **Borda** 198.51.100.0/30 (`r0` .2, simula a Internet). Diagrama completo (mermaid) em `RELATORIO_PROXY.md`.

- **Saída:** `pc1/pc2 → proxy (Squid) → fw → Internet` (antes saíam direto pelo `fw`).
- **Entrada:** `Internet → fw → rp (NGINX) → web` (antes o `fw` liberava `Internet → web` direto).
- `web` continua na DMZ, mas não é mais alcançável diretamente pela Internet.

## 3. Evidências objetivas

### 3.1 LAN → Squid → Internet

Com `fw_proxy.sh depois`, `pc1`/`pc2` direto dão timeout; via Squid (`-x http://10.0.1.12:3128`) funciona (`evidencias/P2_fw_depois.txt`):

```
pc1 DIRETO -> http://10.0.2.10/        : BLOQUEADO (curl exit 28)
pc2 DIRETO -> http://198.51.100.2/     : BLOQUEADO (curl exit 28)
pc1 via Squid -> http://ok.lab/        : HTTP 200
pc2 via Squid -> http://externo.lab/   : HTTP 200
```

### 3.2 Bloqueio de domínio pelo Squid

`ok.lab` e `bloqueado.lab` são o **mesmo IP** (10.0.2.10); o Squid separa pelo nome, via ACL `dstdomain` (`evidencias/P3_squid_acl.txt`):

```
pc1 via Squid -> http://ok.lab/         : HTTP 200
pc1 via Squid -> http://bloqueado.lab/  : HTTP 403
pc2 via Squid -> http://bloqueado.lab/  : HTTP 403
```

`access.log`: `TCP_DENIED/403 ... GET http://bloqueado.lab/ ... HIER_NONE/-` — negado antes de abrir conexão.

### 3.3 Cache

Quatro requisições a `http://ok.lab/admin/`, mais uma forçada com `Cache-Control: no-cache` (`evidencias/P4_squid_cache.txt`):

| # | `X-Cache` | `Age` | Log do Squid | Log do `web` |
|---|---|---|---|---|
| 1 | HIT from proxy | 0 | `TCP_MEM_HIT` / `TCP_REFRESH_UNMODIFIED` | 304 (revalidação) |
| 2–4 | HIT from proxy | 1, 2, 3 | `TCP_MEM_HIT`, `HIER_NONE/-` | nada |
| forçada | MISS from proxy | — | `TCP_MISS` | 200 |

Três provas de que veio do cache: header `X-Cache: HIT` com `Age` crescente; `access.log` com `TCP_MEM_HIT`/`HIER_NONE/-`; e o log do `web` — só 2 requisições para 5 feitas pelo cliente, a prova mais forte por vir de outra máquina.

### 3.4 Internet → NGINX → Web

`r0 → rp` recebe o conteúdo do `web` por trás (`evidencias/P2_fw_depois.txt`):

```
r0 -> http://10.0.2.12/ (rp)  : HTTP 200, corpo "OK-WEB"
```

No log do `web`, a origem é sempre `10.0.2.12` (o `rp`) — nunca o cliente real.

### 3.5 Bloqueio do acesso direto Internet → Web

```
# antes (evidencias/P1_fw_antes.txt)
r0 DIRETO -> http://10.0.2.10/ : HTTP 200

# depois (evidencias/P2_fw_depois.txt)
r0 DIRETO -> http://10.0.2.10/ : BLOQUEADO (curl exit 28)
```

A regra `iptables -A FORWARD -i eth3 -d 10.0.2.10 -j DROP` (`fw/root/fw_proxy.sh`) acumulou pacotes contados — tentativa real, descartada.

### 3.6 Controles no NGINX

Pedia-se pelo menos dois; implementamos quatro, em `rp/etc/nginx/sites-available/default` (`evidencias/P6_nginx.txt`):

1. **`/admin` só para a rede de gerência** (`allow 10.0.3.0/24; deny all`): `r0 → /admin/` = 403; `adm → /admin/` = 200.
2. **Métodos limitados** (`limit_except GET HEAD`): `POST`/`DELETE` = 403.
3. **Rate limiting** (`limit_req zone=por_ip rate=2r/s burst=5`): 15 requisições seguidas → 6×200, 9×429.
4. **Headers de segurança + `server_tokens off`**: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, sem versão do NGINX exposta.

`rp_access.log` registra cada 403/429 com IP, método e caminho.

### 3.7 Defense in Depth

`evidencias/P7_defesa_em_profundidade.txt`.

**Cenário 1 — firewall libera HTTP externo por engano** (`iptables -I FORWARD 1 -i eth3 -o eth1 -p tcp --dport 80 -j ACCEPT`):

```
r0 -> rp/admin/      : HTTP 403   (NGINX ainda protege)
r0 -> rp POST /      : HTTP 403   (NGINX ainda protege)
r0 -> web/admin/ DIRETO : HTTP 200   (sem proteção)
```

O NGINX protege tudo que passa por ele, mas o erro abre um caminho direto ao `web` que nenhuma camada cobre.

**Cenário 2 — `web` comprometido** (testes de saída a partir do `web`):

```
web -> pc1 (LAN)        : bloqueado
web -> proxy/Squid (LAN): bloqueado
web -> adm (Gerência)   : bloqueado
web -> Internet (r0)    : bloqueado
web -> rp (mesma DMZ)   : ALCANÇADO (não passa pelo fw)
```

Default Deny e segmentação impedem LAN/Gerência/Internet, mas o atacante alcança vizinhos da mesma DMZ (`rp`, `dns`) — microssegmentação reduziria isso.

## 4. Como aprendemos (SRL)

**Dúvida → Fonte → Aprendizado → Validação**

| Dúvida/Problema | Fonte consultada | O que aprendemos | Como validamos |
|---|---|---|---|
| Por que a 1ª requisição em `P4_squid_cache.txt` deu `TCP_REFRESH_UNMODIFIED` (304) em vez de `TCP_MISS`? | Doc. oficial do Squid (`wiki.squid-cache.org`, `refresh_pattern` e tags de `access.log`) | O cache persiste entre execuções do script; `TCP_REFRESH_UNMODIFIED` é revalidação (`If-Modified-Since` → `304`), não busca do zero. | Reiniciando o lab, a 1ª requisição virou `TCP_MISS/200` limpo. |
| Como provar que uma resposta veio do cache, sem confiar só no Squid? | Doc. do Squid sobre `access_log` (`TCP_MEM_HIT`, `HIER_NONE`) | O indício mais forte é independente do proxy: o log do servidor de origem (`web`). | Cruzamos header, `access.log` do Squid e log do `web` (seção 3.3). |
| Squid bloqueia por domínio em HTTPS como em HTTP? | Doc. do Squid sobre `CONNECT` e SSL Bump | Em HTTPS o Squid só vê `host:porta` do `CONNECT`; bloquear por caminho exigiria SSL Bump, não configurado. | `https://bloqueado.lab/` deu `curl exit 56` (CONNECT recusado). |
| Por que `REJECT` no firewall contra o IP do `web` não bloqueou `ok.lab`? | Observação direta no lab | Conteúdo em cache é servido sem abrir conexão nova — o firewall nem é consultado. | URLs com `?teste=N` (cache miss) expuseram o `503` real. |
| Como restringir `proxy → web` a 80 e 443 numa regra só? | Manpage `iptables-extensions` (`multiport`) | `-m multiport --dports 80,443` evita duplicar regra. | Contador da regra incrementou nos testes via Squid. |

**Reflexão final**

- **Aprendemos por conta própria:** que "funcionar" ≠ "estar correto" quando há cache — o resultado depende do estado anterior do lab, só cruzando logs de mais de uma máquina dá certeza.
- **Fonte mais útil:** a documentação do Squid sobre as tags do `access_log` — sem ela não explicaríamos a revalidação inesperada.
- **Solução incompleta:** bloquear `/admin` por conteúdo em HTTPS não funciona sem SSL Bump, porque o `CONNECT` não expõe a URL.
- **Faríamos diferente:** reiniciar o lab antes de capturar a evidência de cache (`P4`), pra garantir um `TCP_MISS` limpo na 1ª requisição.
