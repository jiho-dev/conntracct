set -x

# conntrack module is not loaded (and thus eBPF probe cannot be loaded)
# so iptables needs to have a conntrack rule if we don't want to call modprobe manually
sudo ip6tables -t filter -A OUTPUT -m conntrack --ctstate related,established -j ACCEPT
sudo iptables -t filter -A OUTPUT -m conntrack --ctstate related,established -j ACCEPT

# outbound NAT
nic="eth0"
msq=$(sudo iptables -L -t nat -v | grep MASQUERADE | grep $nic)
if [ "$msq" == "" ]; then
	sudo iptables -t nat -A POSTROUTING -o $nic -j MASQUERADE
fi


sudo sysctl net/netfilter/nf_conntrack_tcp_timeout_close_wait=15
sudo sysctl net/netfilter/nf_conntrack_tcp_timeout_fin_wait=15
sudo sysctl net/netfilter/nf_conntrack_tcp_timeout_time_wait=15
sudo sysctl net/netfilter/nf_conntrack_udp_timeout=10
sudo sysctl net/netfilter/nf_conntrack_udp_timeout_stream=30
sudo sysctl net/netfilter/nf_conntrack_icmp_timeout=10
