#!/bin/bash
# Experimentos da Task Squid + NGINX. Requer o lab no ar (kathara lstart).
set -u
export TERM=dumb
cd "$(dirname "$0")"
EVID="evidencias"
mkdir -p "$EVID"

WEB=10.0.2.10
RP=10.0.2.12
SQUID=10.0.1.12:3128

kexec() {
    local maquina=$1; shift
    kathara exec "$maquina" -- bash -c "$*" 2>&1 | grep -v '^$'
}

secao() { { echo; echo "=== $* ==="; } >> "$ARQ"; }

teste() {
    local maquina=$1; shift
    {
        echo
        echo "--- [$maquina] $* ---"
        kexec "$maquina" "$*"
    } >> "$ARQ"
}

# curl via Squid: mostra so o codigo HTTP (ou o erro)
via_squid() {
    local maquina=$1 url=$2
    teste "$maquina" "curl -s -m 8 -o /dev/null -w '$maquina via Squid -> $url : HTTP %{http_code}\n' -x http://$SQUID $url || echo '$maquina via Squid -> $url : FALHOU (curl exit '\$?')'"
}

# curl direto (sem proxy): codigo HTTP ou bloqueio
direto() {
    local maquina=$1 url=$2
    teste "$maquina" "curl -s -m 4 -o /dev/null -w '$maquina DIRETO -> $url : HTTP %{http_code}\n' --noproxy '*' $url || echo '$maquina DIRETO -> $url : BLOQUEADO/SEM RESPOSTA (curl exit '\$?')'"
}

# reinicia o http.server do web (log zerado); pkill e start em chamadas separadas
# para o pkill -f nao casar com a propria linha de comando do bash -c
reinicia_web() {
    kexec web "pkill -f 'http[.]server'" >/dev/null
    sleep 1
    kexec web "cd /var/www/html && nohup python3 -m http.server 80 > /tmp/http80.log 2>&1 &" >/dev/null
    sleep 1
}

echo ">> Verificando o lab..."
if ! kathara list 2>/dev/null | grep -qw 'rp'; then
    echo "ERRO: nao encontrei a maquina 'rp'. Suba o lab com 'kathara lstart' (e rode 'docker build -t kathara-proxy .' antes)."
    exit 1
fi

echo ">> Preparando: logs limpos, web reiniciado, firewall sem regras"
ARQ="$EVID/P0_setup.txt"; : > "$ARQ"
kexec fw "bash /root/fw_proxy.sh remover" >/dev/null
kexec web "pkill -f 's_serve[r]'" >/dev/null
reinicia_web
kexec web "cd /tmp && openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -subj /CN=ok.lab -days 1 >/dev/null 2>&1; nohup openssl s_server -www -accept 443 -cert c.pem -key k.pem > /tmp/https443.log 2>&1 &" >/dev/null
kexec proxy ": > /var/log/squid/access.log" >/dev/null
kexec rp ": > /var/log/nginx/rp_access.log" >/dev/null
sleep 2
teste web "ss -ltn | grep -E ':80|:443'"
teste proxy "ss -ltn | grep 3128"
teste rp "ss -ltn | grep ':80'; nginx -t"
teste r0 "ss -ltn | grep ':80'"

# ---------------------------------------------------------------------------
echo ">> P1 - firewall ANTES (Task anterior): Internet -> web direto"
ARQ="$EVID/P1_fw_antes.txt"; : > "$ARQ"
kexec fw "bash /root/fw_proxy.sh antes" >/dev/null
secao "Internet (r0) -> web DIRETO (deve PASSAR: web exposto)"
direto r0 http://$WEB/
secao "Internet (r0) -> rp (nao permitido ainda no 'antes')"
direto r0 http://$RP/
secao "pc1 DIRETO -> web e -> Internet (LAN sai sem proxy: deve PASSAR)"
direto pc1 http://$WEB/
direto pc1 http://198.51.100.2/
teste fw "iptables -L FORWARD -v -n --line-numbers"

# ---------------------------------------------------------------------------
echo ">> P2 - firewall DEPOIS: Internet -> rp -> web; saida so pelo Squid"
ARQ="$EVID/P2_fw_depois.txt"; : > "$ARQ"
kexec fw "bash /root/fw_proxy.sh depois" >/dev/null
secao "Internet (r0) -> web DIRETO (deve BLOQUEAR)"
direto r0 http://$WEB/
secao "Internet (r0) -> rp (deve PASSAR; o rp busca no web)"
direto r0 http://$RP/
teste r0 "curl -s -m 4 --noproxy '*' http://$RP/ | grep -E 'OK-WEB'"
secao "No web: quem apareceu como cliente? (so o rp, 10.0.2.12)"
teste web "tail -n 3 /tmp/http80.log"
secao "pc1/pc2 DIRETO -> web e -> Internet (deve BLOQUEAR: so o Squid sai)"
direto pc1 http://$WEB/
direto pc2 http://198.51.100.2/
secao "pc1/pc2 VIA SQUID -> web e -> Internet (deve PASSAR)"
via_squid pc1 http://ok.lab/
via_squid pc2 http://externo.lab/
teste fw "iptables -L FORWARD -v -n --line-numbers"

# ---------------------------------------------------------------------------
echo ">> P3 - Squid: ACLs, dominios, HTTPS, cliente"
ARQ="$EVID/P3_squid_acl.txt"; : > "$ARQ"
secao "Acesso permitido (ok.lab) - pc1 e pc2"
via_squid pc1 http://ok.lab/
via_squid pc2 http://ok.lab/
secao "Dominio bloqueado (bloqueado.lab) - ninguem acessa"
via_squid pc1 http://bloqueado.lab/
via_squid pc2 http://bloqueado.lab/
secao "Controle por cliente (restrito.lab) - pc1 pode, pc2 nao"
via_squid pc1 http://restrito.lab/
via_squid pc2 http://restrito.lab/
secao "HTTPS (CONNECT): permitido x bloqueado"
teste pc1 "curl -sk -m 8 -x http://$SQUID https://ok.lab/ | head -n 3 || echo 'falhou'"
teste pc1 "curl -sk -m 8 -o /dev/null -w 'HTTPS ok.lab -> HTTP %{http_code}\n' -x http://$SQUID https://ok.lab/"
teste pc1 "curl -sk -m 8 -o /dev/null -x http://$SQUID https://bloqueado.lab/ ; echo \"HTTPS bloqueado.lab -> curl exit \$? (56 = CONNECT recusado pelo proxy)\""
secao "access.log do Squid (HIT/MISS/DENIED, cliente, metodo, URL)"
teste proxy "cat /var/log/squid/access.log"

# ---------------------------------------------------------------------------
echo ">> P4 - Squid: cache"
ARQ="$EVID/P4_squid_cache.txt"; : > "$ARQ"
kexec proxy ": > /var/log/squid/access.log" >/dev/null
reinicia_web
secao "4 requisicoes seguidas a http://ok.lab/admin/ (header X-Cache e Age mostram se veio do cache)"
for i in 1 2 3 4; do
    teste pc1 "echo \"requisicao $i:\"; curl -s -m 8 -D - -o /dev/null -x http://$SQUID http://ok.lab/admin/ | grep -iE '^(HTTP|X-Cache|Age)'"
done
secao "Requisicao forcada a ir ao servidor (Cache-Control: no-cache)"
teste pc1 "curl -s -m 8 -D - -o /dev/null -H 'Cache-Control: no-cache' -x http://$SQUID http://ok.lab/admin/ | grep -iE '^(HTTP|X-Cache|Age)'"
secao "access.log do Squid: TCP_MISS na 1a, TCP_MEM_HIT nas seguintes"
teste proxy "cat /var/log/squid/access.log"
secao "Log do web: quantas vezes o web realmente atendeu /admin/? (esperado: 2 = 1 MISS + 1 forcada)"
teste web "cat /tmp/http80.log"

# ---------------------------------------------------------------------------
echo ">> P5 - bloqueio por IP (firewall) x por dominio (Squid)"
ARQ="$EVID/P5_ip_vs_dominio.txt"; : > "$ARQ"
secao "Squid: ok.lab e bloqueado.lab tem o MESMO IP ($WEB); o Squid separa pelo nome"
via_squid pc1 http://ok.lab/
via_squid pc1 http://bloqueado.lab/
secao "Firewall bloqueando o IP $WEB para o Squid (REJECT). URL ja em cache continua saindo do cache (o firewall nem e consultado):"
teste fw "iptables -I FORWARD 1 -s 10.0.1.12 -d $WEB -j REJECT --reject-with icmp-host-prohibited"
via_squid pc1 http://ok.lab/
secao "  URLs NAO cacheadas (?teste=N) precisam ir ao web: o firewall derruba o ok.lab (503), que era para passar; o bloqueado.lab segue 403 pelo Squid, que nega antes de tentar conectar"
via_squid pc1 "http://ok.lab/?teste=1"
via_squid pc1 "http://bloqueado.lab/?teste=2"
teste fw "iptables -L FORWARD -v -n --line-numbers | head -4"
teste fw "iptables -D FORWARD -s 10.0.1.12 -d $WEB -j REJECT --reject-with icmp-host-prohibited"
secao "Regra removida: ok.lab volta (URL nova), bloqueado.lab segue 403 so por causa do Squid"
via_squid pc1 "http://ok.lab/?teste=3"
via_squid pc1 "http://bloqueado.lab/?teste=4"

# ---------------------------------------------------------------------------
echo ">> P6 - NGINX (reverse proxy): controles"
ARQ="$EVID/P6_nginx.txt"; : > "$ARQ"
kexec rp ": > /var/log/nginx/rp_access.log" >/dev/null
secao "Controle 1: /admin so para a rede de gerencia (10.0.3.0/24)"
teste r0  "curl -s -m 4 --noproxy '*' -o /dev/null -w 'r0 (Internet) -> rp/admin/ : HTTP %{http_code}\n' http://$RP/admin/"
teste adm "curl -s -m 4 --noproxy '*' -w ' <- adm -> rp/admin/ : HTTP %{http_code}\n' http://$RP/admin/ | grep -E 'OK-ADMIN|HTTP'"
secao "Controle 2: so GET/HEAD (POST e DELETE recebem 403)"
teste r0 "curl -s -m 4 -o /dev/null -w 'GET    / : HTTP %{http_code}\n' http://$RP/"
teste r0 "curl -s -m 4 -o /dev/null -w 'POST   / : HTTP %{http_code}\n' -X POST -d x=1 http://$RP/"
teste r0 "curl -s -m 4 -o /dev/null -w 'DELETE / : HTTP %{http_code}\n' -X DELETE http://$RP/"
secao "Controle 3: headers de seguranca (e server_tokens off: sem versao do nginx)"
teste r0 "curl -sI -m 4 http://$RP/"
secao "Controle 4: rate limiting (2 req/s, burst 5): 15 requisicoes seguidas do mesmo IP"
sleep 2
teste r0 "for i in \$(seq 1 15); do curl -s -m 4 -o /dev/null -w '%{http_code} ' http://$RP/; done; echo"
sleep 2
secao "Log do NGINX: requisicoes suspeitas (403 = negada, 429 = limitada)"
teste rp "grep -E '\" (403|429) ' /var/log/nginx/rp_access.log | head -n 12"
secao "O web ve apenas o rp como cliente (10.0.2.12)"
teste web "tail -n 4 /tmp/http80.log"

# ---------------------------------------------------------------------------
echo ">> P7 - Defense in Depth"
ARQ="$EVID/P7_defesa_em_profundidade.txt"; : > "$ARQ"
secao "Cenario 1: regra ACIDENTAL no fw libera Internet -> DMZ inteira na porta 80"
teste fw "iptables -I FORWARD 1 -i eth3 -o eth1 -p tcp --dport 80 -j ACCEPT"
secao "  O NGINX ainda protege o que passa por ele:"
teste r0 "curl -s -m 4 -o /dev/null -w 'r0 -> rp/admin/ : HTTP %{http_code}  (NGINX segura)\n' http://$RP/admin/"
teste r0 "curl -s -m 4 -o /dev/null -w 'r0 -> rp POST  : HTTP %{http_code}  (NGINX segura)\n' -X POST http://$RP/"
secao "  Mas o web, sem NGINX na frente, fica exposto (limite da defesa):"
teste r0 "curl -s -m 4 -o /dev/null -w 'r0 -> web/admin/ DIRETO : HTTP %{http_code}  (sem protecao)\n' http://$WEB/admin/"
teste fw "iptables -D FORWARD -i eth3 -o eth1 -p tcp --dport 80 -j ACCEPT"
secao "  Regra removida: web volta a ser inacessivel pela Internet"
direto r0 http://$WEB/admin/

secao "Cenario 2: web COMPROMETIDO - o que ele alcanca? (exit 28 = timeout/bloqueado, 7 = recusado = alcancou o host)"
teste web "curl -s -m 3 -o /dev/null http://10.0.1.10:22; echo 'web -> pc1 (LAN) : curl exit '\$?"
teste web "curl -s -m 3 -o /dev/null http://10.0.1.12:3128; echo 'web -> proxy/Squid (LAN) : curl exit '\$?"
teste web "curl -s -m 3 -o /dev/null http://10.0.3.10:22; echo 'web -> adm (Gerencia) : curl exit '\$?"
teste web "curl -s -m 3 -o /dev/null http://198.51.100.2/; echo 'web -> Internet (r0:80, tem servico) : curl exit '\$?"
teste web "curl -s -m 3 -o /dev/null http://$RP/; echo 'web -> rp (mesma DMZ, nao passa pelo fw) : curl exit '\$?"
teste fw "iptables -L FORWARD -v -n --line-numbers"

# ---------------------------------------------------------------------------
echo ">> Limpando: firewall sem regras e listeners de teste encerrados"
ARQ="$EVID/P99_cleanup.txt"; : > "$ARQ"
kexec fw "bash /root/fw_proxy.sh remover" >/dev/null
teste fw "iptables -L FORWARD -n | head -3"
kexec web "pkill -f 's_serve[r]'" >/dev/null 2>&1

echo
echo ">> Feito. Evidencias em $EVID/:"
ls -1 "$EVID" | grep '^P'
