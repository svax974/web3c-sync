# syntax=docker/dockerfile:1
# Compilation croisée native (pas d'émulation) : l'image se construit pour
# linux/amd64 et linux/arm64 depuis n'importe quelle machine.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/syncd ./cmd/syncd \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="web3c-sync" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/svax974/web3c-sync"
COPY --from=build /out/syncd /syncd
# /data appartient à l'utilisateur non-root (65532) : un volume nommé ou un
# `docker run` simple peut y créer la base sans chown préalable.
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME /data
EXPOSE 8080
ENV SYNC_DB=/data/sync.db SYNC_BLOB_DIR=/data/blobs SYNC_LISTEN=:8080
USER nonroot:nonroot
ENTRYPOINT ["/syncd"]
