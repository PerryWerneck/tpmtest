#!/bin/bash

systemctl stop wpa_supplicant

mkdir -p /etc/wpa/client
cd /etc/wpa/client
if [ "$?" != "0" ]; then
	exit 1
fi

setupwpa() {

cat > /etc/wpa/client/wpa_supplicant.conf <<'EOT'

ctrl_interface=/var/run/wpa_client
ctrl_interface_group=wheel
 
network={
    key_mgmt=IEEE8021X
    eap=TLS
    identity="tpmtest"
	ca_cert="/etc/wpa/certs/ca.crt"
    client_cert="/etc/wpa/client/tpmtest.crt"
    private_key="/etc/wpa/client/tpmtest.key"
    private_key_passwd="password"
}
 
EOT

}

if [ ! -e /etc/wpa/client/tpmtest.key ]; then
	cd /etc/wpa/client
	tpmtest genkey gencsr
	if [ "$?" != "0" ]; then
		exit 1
	fi
fi

if [ ! -e /etc/wpa/client/tpmtest.crt ]; then
	cd /etc/wpa/client
	openssl x509 -req -in tpmtest.csr -CA /etc/wpa/certs/ca.crt -CAkey /etc/wpa/certs/ca.key -CAcreateserial -out tpmtest.crt -days 365 -sha256
	if [ "$?" != "0" ]; then
		exit 1
	fi
fi

if [ ! -e /etc/wpa/client/wpa_supplicant.conf ]; then
	setupwpa
fi

ip a add dev ven0 192.168.23.100/24
wpa_supplicant -u -d -t -c /etc/wpa/client/wpa_supplicant.conf -i ven0 -D wired
if [ "$?" != "0" ]; then
	exit 1
fi
