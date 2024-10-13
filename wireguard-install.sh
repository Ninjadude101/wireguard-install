#!/bin/bash

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function randomInternalIPs() {
	local octet_b=$(shuf -i0-255 -n1)
	local octet_c=$(shuf -i0-255 -n1)
	local octet_d=$(($(shuf -i1-64 -n1)*4-4))

	INT_NETWORK="10.${octet_b}.${octet_c}.${octet_d}"
	INT_SERVERIP="10.${octet_b}.${octet_c}.$((${octet_d}+1))"
	INT_CLIENTIP="10.${octet_b}.${octet_c}.$((${octet_d}+2))"
	INT_BCASTIP="10.${octet_b}.${octet_c}.$((${octet_d}+3))"
}

function setOptions() {
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	SERVER_WG_NIC="wg0"
	SERVER_PORT=$(shuf -i49152-65535 -n1)
	CLIENT_DNS_1="1.1.1.1"
	CLIENT_DNS_2="1.0.0.1"
	ALLOWED_IPS="0.0.0.0/0"

	randomInternalIPs
}

function installWireGuard() {
	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	tee "/etc/wireguard/params" <<- EOF
		SERVER_PUB_IP=${SERVER_PUB_IP}
		SERVER_PUB_NIC=${SERVER_PUB_NIC}
		SERVER_WG_NIC=${SERVER_WG_NIC}
		INT_NETWORK=${INT_NETWORK}
		INT_SERVERIP=${INT_SERVERIP}
		INT_CLIENTIP=${INT_CLIENTIP}
		INT_BCASTIP=${INT_BCASTIP}
		SERVER_PORT=${SERVER_PORT}
		SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
		SERVER_PUB_KEY=${SERVER_PUB_KEY}
		CLIENT_DNS_1=${CLIENT_DNS_1}
		CLIENT_DNS_2=${CLIENT_DNS_2}
		ALLOWED_IPS=${ALLOWED_IPS}
	EOF

	# Add server interface
	cat > "/etc/wireguard/${SERVER_WG_NIC}.conf" <<- EOF
		[Interface]
		Address = ${INT_SERVERIP}/30
		ListenPort = ${SERVER_PORT}
		PrivateKey = ${SERVER_PRIV_KEY}
	EOF

	if pgrep firewalld; then
		#FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		cat >> "/etc/wireguard/${SERVER_WG_NIC}.conf" <<- EOF
			PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${INT_NETWORK}/30 masquerade'
			PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${INT_NETWORK}/30 masquerade'
		EOF
	else
		cat >> "/etc/wireguard/${SERVER_WG_NIC}.conf" <<- EOF
			PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
			PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
			PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
			PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
			PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
			PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
			PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
			PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
		EOF
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	newClient
	#echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		#echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		#echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		#echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
		reboot
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Create client file and add the server as a peer
	cat > "/etc/wireguard/${SERVER_WG_NIC}-Client.conf" <<- EOF
		[Interface]
		PrivateKey = ${CLIENT_PRIV_KEY}
		Address = ${INT_CLIENTIP}/32
		DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

		[Peer]
		PublicKey = ${SERVER_PUB_KEY}
		PresharedKey = ${CLIENT_PRE_SHARED_KEY}
		Endpoint = ${ENDPOINT}
		AllowedIPs = ${ALLOWED_IPS}
	EOF

	# Add the client as a peer to the server
	cat >> "/etc/wireguard/${SERVER_WG_NIC}.conf" <<- EOF

		[Peer]
		PublicKey = ${CLIENT_PUB_KEY}
		PresharedKey = ${CLIENT_PRE_SHARED_KEY}
		AllowedIPs = ${INT_CLIENTIP}/32
	EOF

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

initialCheck
setOptions
installWireGuard