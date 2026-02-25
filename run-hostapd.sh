#!/bin/bash
#
# SUSEConnect --product PackageHub/15.7/x86_64
# zypper in hostapd
#
#netns="switch"

setupca() {

	#
	# Step 1 - Create the Certificate Authority (CA)
	#
	mkdir -p /etc/wpa/certs
	
	# Generate CA private key
	openssl genrsa -out /etc/wpa/certs/ca.key 4096

	# Create CA certificate
	openssl req \
		-new -x509 -days 3650 \
		-key /etc/wpa/certs/ca.key \
		-out /etc/wpa/certs/ca.pem \
		-subj "/C=US/ST=State/L=City/O=MyNetwork/CN=TPMTest CA" \
		-addext "basicConstraints=critical,CA:TRUE"	

}

gencerts() {

	#
	# Step 2 - Create the Server Certificate (for hostapd):
	#

	# Generate server private key
	openssl genrsa -out /etc/wpa/certs/server.key 4096

	# Create a certificate signing request (CSR) for the server
	openssl req -new -key /etc/wpa/certs/server.key -out /etc/wpa/certs/server.csr

	# Sign the server CSR with your CA
	openssl x509 -req -in /etc/wpa/certs/server.csr -CA /etc/wpa/certs/ca.crt -CAkey /etc/wpa/certs/ca.key -CAcreateserial -out /etc/wpa/certs/server.crt -days 365

	ln -f /etc/wpa/certs/ca.crt /etc/hostapd.ca.pem
	ln -f /etc/wpa/certs/server.crt /etc/hostapd.server.pem
	ln -f /etc/wpa/certs/server.key /etc/hostapd.server.prv
	
}

setuphostapd() {

cat > /etc/hostapd.eap_user <<'EOT'
# Specific client identity
#"user@example.com"      TLS

# Wildcard for any identity (rely solely on CA certificate validation)
*                       TLS
EOT

cat > /etc/hostapd.conf <<'EOT'
# General settings of hostapd
# ===========================

# Control interface settings
ctrl_interface=/var/run/hostapd
ctrl_interface_group=root

# Enable logging for all modules
logger_syslog=-1
logger_stdout=-1

# Log level
logger_syslog_level=2
logger_stdout_level=2


# Wired 802.1X authentication
# ===========================

# Driver interface type
driver=wired

# Enable IEEE 802.1X authorization
ieee8021x=1
eapol_version=2
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
eap_server=1
eap_user_file=/etc/hostapd.eap_user

# Use port access entry (PAE) group address
# (01:80:c2:00:00:03) when sending EAPOL frames
use_pae_group_addr=1

# Network interface for authentication requests
interface=br0

# WPA2-Enterprise Settings
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP

# TLS Certificate Paths
ca_cert=/etc/hostapd.ca.pem
server_cert=/etc/hostapd.server.pem
private_key=/etc/hostapd.server.prv
# private_key_passwd=### # Uncomment and set password if your key is encrypted

EOT
	
}

setupnet() {
	ip link set dev lo up
	ip a s
	ip link add name br0 type bridge group_fwd_mask 8
	ip link add name dummy0 type dummy
	ip link set dev dummy0 master br0
	ip link add ven0 type veth peer name ven1
	ip link set dev ven1 master br0
	ip link set dev br0 up
	ip addr add dev br0 192.168.23.1/24
	ip link set dev ven1 up
	ip link set dev ven0 up
}

if [ ! -e /etc/wpa/certs/ca.crt ]; then
	setupca
fi

if [ ! -e /etc/wpa/certs/server.key ]; then
	gencerts
fi

setupnet
setuphostapd

# Start hostapd
/usr/sbin/hostapd -dd -K /etc/hostapd.conf




