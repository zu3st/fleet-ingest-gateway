# Dependencies

`fleet-authz` uses only the Go standard library. Elasticsearch is called over plain HTTP(S) with `net/http`.

| Dependency | Used for | Why it is trusted |
| --- | --- | --- |
| `golang:1.27.3-alpine` (pinned by digest) | Building and testing, the CA bundle copied into the image, and setting the owner of the authorizer's key file in `dev/lab-setup.sh` | Docker Official Image maintained by the Go team and Docker |
| `scratch` | Runtime base of `fleet-authz`: only the static binary and CA roots | Empty image, nothing to trust |
| `traefik:v3.7.16` (pinned by digest) | The reverse proxy in the dev stack (production uses RKE2's bundled Traefik) | Docker Official Image from Traefik Labs |
| `ghcr.io/jqlang/jq:1.7.1` (pinned by digest) | JSON handling in the lab scripts only | Official image of the jq project |
| `openssl` (host) | Dev certificates in `dev/gen-certs.sh` only | System package |
| `actions/checkout` v7.0.1, `actions/attest-build-provenance` v4.2.2 (pinned by SHA) | Release workflow: checkout and the signed provenance attestation | Maintained by GitHub |
| `docker/setup-buildx-action` v4.4.1, `docker/login-action` v4.6.0, `docker/metadata-action` v6.2.0, `docker/build-push-action` v7.4.0 (pinned by SHA) | Release workflow: build, tag and push the image to GHCR | Official actions maintained by Docker |
| `rhysd/actionlint:1.7.12` (run locally, `sha256:b1934ee5…`) | Linting the workflow: `docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:1.7.12` | Widely used linter, published by its author |
