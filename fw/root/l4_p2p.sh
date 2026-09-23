#!/bin/bash

LAN_IF=eth0
PORTAS="6881:6999,6969"

REGRA_TCP_IN="-i $LAN_IF -p tcp -m multiport --dports $PORTAS"
REGRA_UDP_IN="-i $LAN_IF -p udp -m multiport --dports $PORTAS"
REGRA_TCP_OUT="-o $LAN_IF -p tcp -m multiport --dports $PORTAS"
REGRA_UDP_OUT="-o $LAN_IF -p udp -m multiport --dports $PORTAS"

remover_regras() {
    for regra in "$REGRA_TCP_IN" "$REGRA_UDP_IN" "$REGRA_TCP_OUT" "$REGRA_UDP_OUT"; do
        while iptables -D FORWARD $regra -j P2P 2>/dev/null; do :; done
    done
}

if [ "$1" = "remover" ]; then
    remover_regras
    iptables -F P2P 2>/dev/null
    iptables -X P2P 2>/dev/null
    echo "Bloqueio P2P removido."
    exit 0
fi

iptables -N P2P 2>/dev/null
iptables -F P2P
iptables -A P2P -j DROP

remover_regras

iptables -I FORWARD 1 $REGRA_UDP_OUT -j P2P
iptables -I FORWARD 1 $REGRA_TCP_OUT -j P2P
iptables -I FORWARD 1 $REGRA_UDP_IN -j P2P
iptables -I FORWARD 1 $REGRA_TCP_IN -j P2P

echo "Bloqueio P2P aplicado:"
iptables -L FORWARD -v -n --line-numbers | head -7
iptables -L P2P -v -n
