#!/bin/sh
# Local CA and one certificate per tenant ingest host (dev only, files under dev/certs/).
set -eu
cd "$(dirname "$0")"
mkdir -p certs
cd certs
if [ ! -f ca.crt ]; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
		-subj '/CN=fleet-ingest-gateway dev CA' -keyout ca.key -out ca.crt 2>/dev/null
fi
for tenant in acme globex; do
	host="ingest-$tenant.local"
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$host" \
		-keyout "ingest-$tenant.key" -out "ingest-$tenant.csr" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host" > ext.cnf
	openssl x509 -req -in "ingest-$tenant.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
		-days 365 -extfile ext.cnf -out "ingest-$tenant.crt" 2>/dev/null
	rm -f "ingest-$tenant.csr" ext.cnf
done
# Traefik runs as uid 65532 and must read the keys; the CA key stays private.
chmod 644 ingest-*.key ingest-*.crt ca.crt
chmod 600 ca.key
ls -1
