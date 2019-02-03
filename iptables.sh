#!/usr/bin/env /bin/bash

iptables -F -t filter
iptables -F -t nat
for cq_ in \
	"iptables -X \$chain" \
	"iptables -N \$chain";
do
	for chain in \
		"SNFLD" \
		"SNFLD_DROP" \
		"IDROP" \
		"ODROP" \
		"FDROP" \
		"TEA_FIREWALL" \
		"DOCKER" \
		"DOCKER-USER" \
		"DOCKER-ISOLATION-STAGE-1";
	do
		bash -c "${cq_/\$chain/$chain}" >> /dev/null 2>&1
	done;
done;

iptables -A PREROUTING -t nat -p tcp -m tcp --dport 48001 -j DNAT -t nat --to-destination 104.168.127.243:48588
iptables -A PREROUTING -t nat -p tcp -m tcp --dport 48002 -j DNAT -t nat --to-destination 69.12.94.61:48588
iptables -A PREROUTING -t nat -p tcp -m tcp --dport 48003 -j DNAT -t nat --to-destination 107.150.7.117:48588

iptables -A PREROUTING -t nat -p tcp -m tcp --dport 38001 -j DNAT -t nat --to-destination 104.168.127.243:38588
iptables -A PREROUTING -t nat -p tcp -m tcp --dport 38002 -j DNAT -t nat --to-destination 69.12.94.61:38588
iptables -A PREROUTING -t nat -p tcp -m tcp --dport 38003 -j DNAT -t nat --to-destination 107.150.7.117:38588

iptables -A PREROUTING -t nat -s 69.12.94.61/32 -p tcp -m tcp --dport 80 -j DNAT -t nat --to-destination 173.254.196.2:80
iptables -A PREROUTING -t nat -s 69.12.94.61/32 -p tcp -m tcp --dport 443 -j DNAT -t nat --to-destination 173.254.196.2:443

iptables -A PREROUTING -t nat -m addrtype --dst-type LOCAL -t nat -j DOCKER
iptables -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -t nat -j DOCKER
iptables -A POSTROUTING -t nat -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
iptables -A POSTROUTING -t nat -s 7.7.7.0/24 ! -d 7.7.7.0/24 -j SNAT -t nat --to-source 68.183.184.174
iptables -A POSTROUTING -t nat -j MASQUERADE
iptables -A DOCKER -t nat -i docker0 -j RETURN

iptables -A IDROP -j LOG --log-prefix "[INPUT_LOG:DROP]: " --log-level 6
iptables -A IDROP -j DROP
iptables -A ODROP -j LOG --log-prefix "[OUTPUT_LOG:DROP]: " --log-level 6
iptables -A ODROP -j DROP
iptables -A FDROP -j LOG --log-prefix "[FORWARD_LOG:DROP]: " --log-level 6
iptables -A FDROP -j DROP
iptables -A SNFLD_DROP -j LOG --log-prefix "[SNFLD:DROP]: " --log-level 6
iptables -A SNFLD_DROP -j DROP

iptables -A SNFLD -m limit --limit 1/second --limit-burst 10 -j RETURN
iptables -A SNFLD ! -s 127.0.0.0/24 -j SNFLD_DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -s 7.7.7.0/24 -j ACCEPT
iptables -A INPUT -d 7.7.7.0/24 -j ACCEPT
iptables -A INPUT -g TEA_FIREWALL
iptables -A INPUT ! -s 127.0.0.0/24 -p tcp --syn -j SNFLD
iptables -A INPUT ! -s 127.0.0.0/24 -p icmp -m limit --limit 1/second --limit-burst 1 -j ACCEPT
iptables -A INPUT ! -s 127.0.0.0/24 -p icmp -m icmp --icmp-type address-mask-request -j IDROP
iptables -A INPUT ! -s 127.0.0.0/24 -p icmp -m icmp --icmp-type timestamp-request -j IDROP
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 64777 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 43080 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 43443 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 38588 -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
for cq_ in \
	"iptables -A INPUT -p tcp -m tcp --dport \$port -m state --state NEW,ESTABLISHED -m recent --name SSH_HANDLER --set -j ACCEPT" \
	"iptables -A INPUT -p tcp -m tcp --dport \$port -m state --state NEW -m recent --name SSH_HANDLER --update --seconds 600 --hitcount 10 -j IDROP"; 
do
	for port in {48588,48001,48002,48003,38001,38002,38003}; do
		bash -c "${cq_/\$port/$port}";
	done;
done;
iptables -A INPUT -m state --state INVALID -j IDROP
iptables -A INPUT -j IDROP

iptables -A FORWARD -j DOCKER-USER
iptables -A FORWARD -j DOCKER-ISOLATION-STAGE-1
iptables -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -o docker0 -j DOCKER
iptables -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
iptables -A FORWARD -i docker0 -o docker0 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 7.7.7.0/24 -j ACCEPT
iptables -A FORWARD -m state --state INVALID -j FDROP

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -s 7.7.7.0/24 -j ACCEPT
iptables -A OUTPUT -d 7.7.7.0/24 -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
for port in {48588,48001,48002,48003,38001,38002,38003}; do
	iptables -A OUTPUT -p tcp -m tcp --dport $port -j ACCEPT
done;
iptables -A OUTPUT -p udp -m udp --dport 64777 -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT
iptables -A OUTPUT -m state --state INVALID -j ODROP
iptables -A OUTPUT -j ODROP

iptables -A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
iptables -A DOCKER-ISOLATION-STAGE-1 -j RETURN
iptables -A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
iptables -A DOCKER-ISOLATION-STAGE-2 -j RETURN
iptables -A DOCKER-USER -j RETURN
iptables -A DOCKER -j RETURN

iptables -A TEA_FIREWALL -s 176.119.4.7/32 -j DROP
iptables -A TEA_FIREWALL -s 193.106.31.1/32 -j DROP
iptables -A TEA_FIREWALL -s 185.53.91.3/32 -j DROP
iptables -A TEA_FIREWALL -s 189.225.82.1/32 -j DROP
iptables -A TEA_FIREWALL -s 191.193.184.2/32 -j DROP
iptables -A TEA_FIREWALL -s 185.176.27.7/32 -j DROP
iptables -A TEA_FIREWALL -s 190.99.54.1/32 -j DROP
iptables -A TEA_FIREWALL -s 182.0.180.1/32 -j DROP
iptables -A TEA_FIREWALL -s 177.250.0.9/32 -j DROP
iptables -A TEA_FIREWALL -s 113.203.237.8/32 -j DROP
iptables -A TEA_FIREWALL -s 202.29.221.2/32 -j DROP
iptables -A TEA_FIREWALL -s 41.189.166.1/32 -j DROP
iptables -A TEA_FIREWALL -s 185.176.27.6/32 -j DROP
iptables -A TEA_FIREWALL -s 122.180.80.2/32 -j DROP
iptables -A TEA_FIREWALL -s 85.192.184.8/32 -j DROP
iptables -A TEA_FIREWALL -s 177.86.157.6/32 -j DROP
iptables -A TEA_FIREWALL -s 13.232.120.2/32 -j DROP
iptables -A TEA_FIREWALL -s 51.38.131.1/32 -j DROP
iptables -A TEA_FIREWALL -s 77.72.85.1/32 -j DROP
iptables -A TEA_FIREWALL -s 1.160.13.3/32 -j DROP
iptables -A TEA_FIREWALL -s 36.65.72.1/32 -j DROP
iptables -A TEA_FIREWALL -s 61.246.140.2/32 -j DROP
iptables -A TEA_FIREWALL -s 115.68.181.2/32 -j DROP
iptables -A TEA_FIREWALL -s 191.55.200.1/32 -j DROP
iptables -A TEA_FIREWALL -s 119.28.88.1/32 -j DROP
iptables -A TEA_FIREWALL -s 62.213.107.1/32 -j DROP
iptables -A TEA_FIREWALL -s 5.188.65.7/32 -j DROP
iptables -A TEA_FIREWALL -s 12.19.102.1/32 -j DROP
iptables -A TEA_FIREWALL -s 117.198.150.2/32 -j DROP
iptables -A TEA_FIREWALL -s 184.105.139.1/32 -j DROP
iptables -A TEA_FIREWALL -s 222.124.200.1/32 -j DROP
iptables -A TEA_FIREWALL -s 187.60.41.1/32 -j DROP
iptables -A TEA_FIREWALL -s 180.244.248.1/32 -j DROP
iptables -A TEA_FIREWALL -j RETURN

