#!/bin/bash

setupca() {

	mkdir /etc/wpa/certs
	
	#
	# Step 1 - Create the Certificate Authority (CA)
	#

	# Generate CA private key
	openssl genrsa -out /etc/wpa/certs/ca.key 4096

	# Create CA certificate request
 	openssl req -new -key /etc/wpa/certs/ca.key -out /etc/wpa/certs/ca.csr

	# Sign CA certificate 
    openssl x509 -req -days 365 -in /etc/wpa/certs/ca.csr -signkey /etc/wpa/certs/ca.key -out /etc/wpa/certs/ca.crt

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

	ln -f /etc/wpa/certs/ca.crt 		/etc/hostapd.ca.pem
	ln -f /etc/wpa/certs/server.csr		/etc/hostapd.server.pem
	ln -f /etc/wpa/certs/server.key		/etc/hostapd.server.prv
	
}

setupca
gencerts


