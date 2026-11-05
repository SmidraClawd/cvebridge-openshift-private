FROM docker.io/library/golang:1.27.3 AS build
WORKDIR /src
# Dependencies are shipped in vendor; compilation never downloads Go modules.
ENV GOPROXY=off GOTOOLCHAIN=local
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/cvebridge ./cmd/cvebridge \
    && mkdir -p /out/data && chmod 0770 /out/data && chown 10001:0 /out/data

FROM scratch
# CA certificates are supplied by the cluster as read-only volumes.
# Copy the parent so /data retains its 0770 mode and group ownership.
COPY --from=build /out/ /
USER 10001:0
EXPOSE 8001
ENTRYPOINT ["/cvebridge"]
