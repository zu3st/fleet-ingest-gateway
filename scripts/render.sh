#!/bin/sh
# Renders the Traefik configuration for the dev stack and the example RKE2 values.
set -eu
cd "$(dirname "$0")/.."
go() {
	docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache \
		-v "$PWD":/src -w /src golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb go "$@"
}
go run ./cmd/render -values deploy/values/dev.json -format file > dev/traefik/dynamic/gateway.yaml
go run ./cmd/render -values deploy/values/example-rke2.json -format crd > deploy/k8s/example-rke2-tenants.yaml
echo "rendered dev/traefik/dynamic/gateway.yaml and deploy/k8s/example-rke2-tenants.yaml"
