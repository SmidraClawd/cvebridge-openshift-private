FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/cvebridge ./cmd/cvebridge \
    && mkdir -p /out/data && chmod 0770 /out/data && chown 10001:0 /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Copy the parent so /data retains its 0770 mode and group ownership.
COPY --from=build /out/ /
USER 10001:0
EXPOSE 8001
ENTRYPOINT ["/cvebridge"]
