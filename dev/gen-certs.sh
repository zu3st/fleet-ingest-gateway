#!/bin/sh
# Local CA, one certificate per tenant ingest host and one for the lab's Fleet
# Server forward (dev only, files under dev/certs/).
set -eu
cd "$(dirname "$0")"
mkdir -p certs
cd certs
if [ ! -f ca.crt ]; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
		-subj '/CN=fleet-ingest-gateway dev CA' -keyout ca.key -out ca.crt 2>/dev/null
fi
# file name:host name
for cert in ingest-acme:ingest-acme.local ingest-globex:ingest-globex.local fleet-server:fleet-server; do
	name=${cert%%:*} host=${cert#*:}
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$host" \
		-keyout "$name.key" -out "$name.csr" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host" > ext.cnf
	openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
		-days 365 -extfile ext.cnf -out "$name.crt" 2>/dev/null
	rm -f "$name.csr" ext.cnf
done
# Traefik runs as uid 65532 and must read the keys; the CA key stays private.
chmod 644 ingest-*.key ingest-*.crt fleet-server.key fleet-server.crt ca.crt
chmod 600 ca.key
ls -1
