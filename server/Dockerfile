# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/syncd ./cmd/syncd

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="web3c-sync" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/svax974/web3c-sync"
COPY --from=build /out/syncd /syncd
VOLUME /data
EXPOSE 8080
ENV SYNC_DB=/data/sync.db SYNC_BLOB_DIR=/data/blobs SYNC_LISTEN=:8080
USER nonroot:nonroot
ENTRYPOINT ["/syncd"]
