#!/bin/bash
set -u
export TERM=dumb
cd "$(dirname "$0")"
EVID="evidencias"
mkdir -p "$EVID"

PC1_IP=10.0.1.10
WEB_IP=10.0.2.10
DNS_IP=10.0.2.11

kexec() {
    local maquina=$1; shift
    kathara exec "$maquina" -- bash -c "$*" 2>&1
}

kexec_bg() {
    local maquina=$1; shift
    kathara exec "$maquina" -- bash -c "$* &" >/dev/null 2>&1
}

secao() {
    { echo; echo "=== $* ==="; } >> "$ARQ"
}

teste() {
    local maquina=$1; shift
    {
        echo
        echo "--- [$maquina] $* ---"
        kexec "$maquina" "$*"
    } >> "$ARQ"
}

echo ">> Verificando se o lab esta de pe..."
if ! kathara list 2>/dev/null | grep -qi fw; then
    echo "ERRO: nao encontrei a maquina 'fw' rodando. Rode 'kathara lstart' primeiro."
    exit 1
fi

echo ">> Preparando listeners de teste em web e pc1..."
ARQ="$EVID/00_setup.txt"
: > "$ARQ"

kexec web "pkill -f bt_peer.py; pkill -f 'http.server'" >/dev/null 2>&1
kexec pc1 "pkill -f bt_peer.py" >/dev/null 2>&1
sleep 1

kexec_bg web "nohup python3 /shared/bt_peer.py server 6881 > /tmp/srv6881.log 2>&1"
kexec_bg web "nohup python3 /shared/bt_peer.py server 443 > /tmp/srv443.log 2>&1"
kexec web "mkdir -p /tmp/www/public /tmp/www/admin && echo OK-PUBLICO > /tmp/www/public/index.html && echo OK-ADMIN > /tmp/www/admin/index.html"
kexec_bg web "cd /tmp/www && nohup python3 -m http.server 80 > /tmp/http80.log 2>&1"

kexec_bg pc1 "nohup python3 /shared/bt_peer.py server 6881 > /tmp/srv6881.log 2>&1"

sleep 2
teste web "ps aux | grep -E 'bt_peer|http.server' | grep -v grep"
teste pc1 "ps aux | grep bt_peer | grep -v grep"
echo "   listeners no ar (ver $ARQ)"

fw_baseline() { kexec fw "bash /root/l4_p2p.sh remover; bash /root/l7_dpi.sh remover" >/dev/null; }
fw_l4()       { kexec fw "bash /root/l4_p2p.sh"       >/dev/null; }
fw_l7()       { kexec fw "bash /root/l7_dpi.sh"        >/dev/null; }

contadores() {
    secao "contadores no fw"
    teste fw "iptables -L FORWARD -v -n --line-numbers | head -10"
    teste fw "iptables -L P2P -v -n 2>/dev/null || echo '(cadeia P2P nao existe)'"
    teste fw "iptables -L L7 -v -n 2>/dev/null || echo '(cadeia L7 nao existe)'"
    teste fw "iptables -L L7HTTP -v -n 2>/dev/null || echo '(cadeia L7HTTP nao existe)'"
}

echo ">> E0 - baseline (sem regras)"
ARQ="$EVID/E0_baseline.txt"; : > "$ARQ"
fw_baseline

secao "BT cliente pc1 -> web:6881 (deve PASSAR)"
teste pc1 "timeout 8 python3 /shared/bt_peer.py client $WEB_IP 6881"
secao "HTTP pc1 -> web /public/ e /admin/ (devem PASSAR os dois, ainda sem controle)"
teste pc1 "curl -s -o /dev/null -w 'GET /public/ -> %{http_code}\n' --max-time 4 http://$WEB_IP/public/"
teste pc1 "curl -s -o /dev/null -w 'GET /admin/ -> %{http_code}\n' --max-time 4 http://$WEB_IP/admin/"
contadores

echo ">> E1 - so L4 (bloqueio por porta)"
ARQ="$EVID/E1_l4.txt"; : > "$ARQ"
fw_l4

secao "E1  - BT cliente pc1 -> web:6881 (deve BLOQUEAR)"
teste pc1 "timeout 8 python3 /shared/bt_peer.py client $WEB_IP 6881"
secao "E1b - BT peer da LAN SERVINDO: web -> pc1:6881 (deve BLOQUEAR)"
teste web "timeout 8 python3 /shared/bt_peer.py client $PC1_IP 6881"
secao "E1c - BT cliente pc1 -> web:443 (evasao de porta - deve PASSAR, limitacao do L4)"
teste pc1 "timeout 8 python3 /shared/bt_peer.py client $WEB_IP 443"
teste web "tail -n 3 /tmp/srv443.log"
contadores

echo ">> E2 - so L7 (DPI por assinatura)"
ARQ="$EVID/E2_l7.txt"; : > "$ARQ"
fw_baseline
fw_l7

secao "E2  - BT cliente pc1 -> web:443 (mesma porta do E1c, agora deve BLOQUEAR pelo conteudo)"
secao "  nota: o TCP handshake (SYN/SYN-ACK/ACK) nao carrega dado, entao 'conecta' mesmo"
secao "  bloqueado - quem confirma o bloqueio e o servidor NUNCA receber os 68 bytes:"
teste pc1 "timeout 8 python3 /shared/bt_peer.py client $WEB_IP 443"
teste web "tail -n 3 /tmp/srv443.log"
secao "E2b - trafego NAO-BT pc1 -> web:443 (deve PASSAR - L7 olha o conteudo, nao a porta)"
teste pc1 "timeout 8 python3 /shared/bt_peer.py client $WEB_IP 443 --plain"
secao "E2c - consulta DHT pc1 -> web:33445/udp, porta fora do range do L4 (deve BLOQUEAR pelo conteudo)"
teste pc1 "timeout 8 python3 /shared/bt_peer.py dht $WEB_IP 33445"
secao "E2d - HTTP pc1 -> web /public/ e /admin/ (so /admin/ deve BLOQUEAR, com RST)"
teste pc1 "curl -s -o /dev/null -w 'GET /public/ -> %{http_code}\n' --max-time 4 http://$WEB_IP/public/"
teste pc1 "curl -s -o /dev/null -w 'GET /admin/ -> %{http_code}\n' --max-time 4 http://$WEB_IP/admin/ || echo 'GET /admin/ -> conexao recusada/resetada'"
contadores

echo ">> E3 - L4 + L7 juntos"
ARQ="$EVID/E3_l4_l7.txt"; : > "$ARQ"
fw_l4
fw_l7

secao "E3a - BT cliente pc1 -> web:6881 (bloqueado pelo L4)"
teste pc1 "timeout 8 python3 /shared/bt_peer.py client $WEB_IP 6881"
secao "E3b - BT cliente pc1 -> web:443 (L4 deixaria passar, L7 bloqueia)"
teste pc1 "timeout 8 python3 /shared/bt_peer.py client $WEB_IP 443"
teste web "tail -n 3 /tmp/srv443.log"
secao "E3c - HTTP /admin/ (bloqueado pelo L7)"
teste pc1 "curl -s -o /dev/null -w 'GET /admin/ -> %{http_code}\n' --max-time 4 http://$WEB_IP/admin/ || echo 'GET /admin/ -> conexao recusada/resetada'"
contadores

echo ">> E4 - filtro de DNS (dominio e categoria)"
ARQ="$EVID/E4_dns.txt"; : > "$ARQ"
fw_baseline
kexec dns "bash /root/dns_filter.sh"

secao "E4a - loja.exemplo (PERMITIDO - deve resolver pro IP do web)"
teste pc1 "dig @$DNS_IP loja.exemplo +short +time=3"
secao "E4b - filmes-gratis.exemplo (BLOQUEADO - dominio especifico)"
teste pc1 "dig @$DNS_IP filmes-gratis.exemplo +short +time=3"
secao "E4c - serie-online.exemplo e torrent-facil.exemplo (BLOQUEADOS - categoria)"
teste pc1 "dig @$DNS_IP serie-online.exemplo +short +time=3"
teste pc1 "dig @$DNS_IP torrent-facil.exemplo +short +time=3"
secao "log de consultas no servidor dns (mostra que ele viu os 4 pedidos)"
teste dns "tail -n 12 /tmp/dnsmasq.log"

kexec dns "bash /root/dns_filter.sh remover"

echo ">> Limpando: removendo regras do fw e encerrando listeners de teste"
ARQ="$EVID/99_cleanup.txt"; : > "$ARQ"
fw_baseline
contadores
kexec web "pkill -f bt_peer.py; pkill -f 'http.server'" >/dev/null 2>&1
kexec pc1 "pkill -f bt_peer.py" >/dev/null 2>&1
kexec dns "bash /root/dns_filter.sh remover" >/dev/null 2>&1

echo
echo ">> Feito. Evidencias em $EVID/:"
ls -1 "$EVID"
