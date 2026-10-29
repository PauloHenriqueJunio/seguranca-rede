#!/bin/bash
# Politica de perimetro (Default Deny) para a topologia com Squid e NGINX.
#   bash fw_proxy.sh antes    -> Internet -> web direto (Task anterior)
#   bash fw_proxy.sh depois   -> Internet -> rp -> web; saida da LAN so pelo Squid
#   bash fw_proxy.sh remover  -> limpa tudo e volta a politica ACCEPT (estado do boot)

PROXY=10.0.1.12
WEB=10.0.2.10
RP=10.0.2.12

LAN_IF=eth0
DMZ_IF=eth1
MGT_IF=eth2
WAN_IF=eth3

base() {
    iptables -F FORWARD
    iptables -P FORWARD DROP
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

case "$1" in
antes)
    base
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -s 10.0.1.0/24 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $DMZ_IF -s 10.0.1.0/24 -d 10.0.2.0/24 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A FORWARD -i $WAN_IF -o $DMZ_IF -d $WEB -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
    ;;
depois)
    base
    # Saida: somente o Squid (proxy) fala com a Internet e com o web
    iptables -A FORWARD -i $LAN_IF -o $WAN_IF -s $PROXY -m conntrack --ctstate NEW -j ACCEPT
    iptables -A FORWARD -i $LAN_IF -o $DMZ_IF -s $PROXY -d $WEB -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
    # Entrada: Internet e Gerencia chegam somente ao rp (porta 80)
    iptables -A FORWARD -i $WAN_IF -o $DMZ_IF -d $RP -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A FORWARD -i $MGT_IF -o $DMZ_IF -d $RP -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
    # Regra explicita (so para o contador): Internet -> web direto e descartado
    iptables -A FORWARD -i $WAN_IF -d $WEB -j DROP
    ;;
remover)
    iptables -F FORWARD
    iptables -P FORWARD ACCEPT
    echo "Politica de perimetro removida (FORWARD ACCEPT)."
    exit 0
    ;;
*)
    echo "Uso: bash fw_proxy.sh antes|depois|remover"
    exit 1
    ;;
esac

echo "Politica '$1' aplicada:"
iptables -L FORWARD -v -n --line-numbers
