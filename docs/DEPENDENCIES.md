# Dependencies

`fleet-authz` and `cmd/render` use only the Go standard library; `go.mod` has no
requirements. Elasticsearch is called over plain HTTP(S) with `net/http`.

| Dependency | Used for | Why it is trusted |
| --- | --- | --- |
| `golang:1.27.3-alpine` (pinned by digest) | Building and testing; source of the CA bundle copied into the image | Docker Official Image maintained by the Go team and Docker |
| `scratch` | Runtime base of `fleet-authz`: only the static binary and CA roots | Empty image, nothing to trust |
| `traefik:v3.7.16` (pinned by digest) | The reverse proxy in the dev stack; production uses RKE2's bundled Traefik | Docker Official Image from Traefik Labs |
| `ghcr.io/jqlang/jq:1.7.1` (pinned by digest) | JSON handling in the lab scripts only | Official image of the jq project |
| `openssl` (host) | Dev certificates in `dev/gen-certs.sh` only | System package |
