# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go vet ./... && go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/fleet-authz ./cmd/fleet-authz

# Static binary, system CA roots, non-root.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/fleet-authz /fleet-authz
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/fleet-authz", "healthcheck"]
ENTRYPOINT ["/fleet-authz"]
