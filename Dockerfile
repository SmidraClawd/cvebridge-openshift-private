FROM docker.io/library/golang:1.27.3 AS build
WORKDIR /src
ENV GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/cvebridge/ ./cmd/cvebridge/
COPY internal/bridge/ ./internal/bridge/
# All dependencies are local. A source fingerprint identifies the running build.
RUN build_id="$(find go.mod go.sum cmd internal/bridge vendor -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-12)" \
    && mkdir -p /out/rootfs/data \
    && go build -mod=vendor -trimpath -ldflags="-s -w -X main.version=latest-${build_id}" -o /out/cvebridge ./cmd/cvebridge \
    && chmod 0755 /out/cvebridge \
    && chmod 0770 /out/rootfs/data

FROM scratch
COPY --from=build --chown=10001:0 /out/cvebridge /cvebridge
# Copy the parent to preserve /data's 0770 mode for OpenShift's group 0.
COPY --from=build --chown=10001:0 /out/rootfs/ /
# CA certificates are supplied by the cluster as read-only volumes.
USER 10001:0
EXPOSE 8001
ENTRYPOINT ["/cvebridge"]
