# syntax=docker/dockerfile:1
# Multi-stage build for the quokka SaaS binary at cmd/quokka.
# Legacy CLI is built off the legacy-cli branch; this image is SaaS-only.

FROM golang:1.25-alpine AS build
WORKDIR /src

# Pre-cache deps
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static, stripped, no cgo (modernc.org/sqlite is pure Go).
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/quokka ./cmd/quokka

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/quokka /quokka
USER nonroot:nonroot
ENTRYPOINT ["/quokka"]
