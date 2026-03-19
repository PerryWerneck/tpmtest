#!/bin/bash

if [ "${UID}" != "0" ]; then
	sudo $0 $@
	exit $?
fi

systemctl stop wpa_supplicant

mkdir -p /etc/wpa/client
cd /etc/wpa/client
if [ "$?" != "0" ]; then
	exit 1
fi

setupwpa() {

cat > /etc/wpa/client/wpa_supplicant_no_tpm.conf <<'EOT'

ctrl_interface=/var/run/wpa_client
ctrl_interface_group=wheel
 
network={
    key_mgmt=IEEE8021X
    eap=TLS
    identity="no-tpm"
	ca_cert="/etc/wpa/certs/ca.crt"
    client_cert="/etc/wpa/client/client.crt"
    private_key="/etc/wpa/client/client.key"
    private_key_passwd="password"
}
 
EOT

}

if [ ! -e /etc/wpa/client/client.csr ]; then
	cd /etc/wpa/client
	rm -f client.*
	openssl req -new -newkey rsa:4096 -nodes -keyout /etc/wpa/client/client.key -out /etc/wpa/client/client.csr -sha256
	openssl rsa -engine tpm2tss -inform engine -in "/etc/wpa/client/client.key" -noout -modulus | openssl md5
	openssl req -noout -modulus -in client.csr | openssl md5
fi

if [ ! -e /etc/wpa/client/client.crt ]; then
	cd /etc/wpa/client
	
	# Sign the server CSR with your CA
	openssl x509 -req -in /etc/wpa/client/client.csr -CA /etc/wpa/certs/ca.crt -CAkey /etc/wpa/certs/ca.key -CAcreateserial -out /etc/wpa/client/client.crt -days 365
	if [ "$?" != "0" ]; then
		exit 1
	fi
fi

if [ ! -e /etc/wpa/client/wpa_supplicant.conf ]; then
	setupwpa
fi

ip a add dev ven0 192.168.23.100/24
wpa_supplicant -u -d -t -c /etc/wpa/client/wpa_supplicant_no_tpm.conf -i ven0 -D wired
if [ "$?" != "0" ]; then
	exit 1
fi
