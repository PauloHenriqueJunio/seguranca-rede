#!/bin/bash

LAN_IF=eth0
DMZ_IF=eth1

R_BT_IN=(-i "$LAN_IF" -p tcp -m string --algo bm --hex-string "|13|BitTorrent protocol" -j L7)
R_BT_OUT=(-o "$LAN_IF" -p tcp -m string --algo bm --hex-string "|13|BitTorrent protocol" -j L7)
R_DHT_IN=(-i "$LAN_IF" -p udp -m string --algo bm --string "d1:ad2:id20:" -j L7)
R_DHT_OUT=(-o "$LAN_IF" -p udp -m string --algo bm --string "d1:ad2:id20:" -j L7)
R_HTTP_ADMIN=(-i "$LAN_IF" -o "$DMZ_IF" -p tcp --dport 80 -m string --algo bm --string "GET /admin" -j L7HTTP)

remover_regras() {
    while iptables -D FORWARD "${R_BT_IN[@]}" 2>/dev/null; do :; done
    while iptables -D FORWARD "${R_BT_OUT[@]}" 2>/dev/null; do :; done
    while iptables -D FORWARD "${R_DHT_IN[@]}" 2>/dev/null; do :; done
    while iptables -D FORWARD "${R_DHT_OUT[@]}" 2>/dev/null; do :; done
    while iptables -D FORWARD "${R_HTTP_ADMIN[@]}" 2>/dev/null; do :; done
}

if [ "$1" = "remover" ]; then
    remover_regras
    iptables -F L7 2>/dev/null
    iptables -X L7 2>/dev/null
    iptables -F L7HTTP 2>/dev/null
    iptables -X L7HTTP 2>/dev/null
    echo "DPI L7 removido."
    exit 0
fi

iptables -N L7 2>/dev/null
iptables -F L7
iptables -A L7 -j DROP

iptables -N L7HTTP 2>/dev/null
iptables -F L7HTTP
iptables -A L7HTTP -p tcp -j REJECT --reject-with tcp-reset

remover_regras

iptables -I FORWARD 1 "${R_HTTP_ADMIN[@]}"
iptables -I FORWARD 1 "${R_DHT_OUT[@]}"
iptables -I FORWARD 1 "${R_DHT_IN[@]}"
iptables -I FORWARD 1 "${R_BT_OUT[@]}"
iptables -I FORWARD 1 "${R_BT_IN[@]}"

echo "DPI L7 aplicado:"
iptables -L FORWARD -v -n --line-numbers | head -8
iptables -L L7 -v -n
iptables -L L7HTTP -v -n
