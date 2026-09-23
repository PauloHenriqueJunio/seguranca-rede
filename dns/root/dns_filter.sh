#!/bin/bash

PIDFILE=/tmp/dns_filter.pid

parar() {
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null
        rm -f "$PIDFILE"
    fi
    pkill dnsmasq 2>/dev/null
}

if [ "$1" = "remover" ]; then
    parar
    echo "Filtro de DNS desligado."
    exit 0
fi

parar
sleep 1

dnsmasq \
    --no-daemon \
    --port=53 \
    --address=/loja.exemplo/10.0.2.10 \
    --address=/filmes-gratis.exemplo/0.0.0.0 \
    --address=/serie-online.exemplo/0.0.0.0 \
    --address=/torrent-facil.exemplo/0.0.0.0 \
    --log-queries \
    > /tmp/dnsmasq.log 2>&1 &

echo $! > "$PIDFILE"
sleep 1

echo "Filtro de DNS ligado (PID $(cat "$PIDFILE"))."
echo "Permitido:  loja.exemplo"
echo "Bloqueado:  filmes-gratis.exemplo (site especifico)"
echo "Bloqueado:  serie-online.exemplo, torrent-facil.exemplo (categoria)"
