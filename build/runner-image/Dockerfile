# syntax=docker/dockerfile:1
# Runner image: the per-agent container the worker spawns. Same binary
# as the server but with the in-container ENTRYPOINT set to `quokka agent run`.
#
# Build args:
#   SERVER_VERSION  e.g. 0.5.0
#   GIT_SHA         short sha used in the image tag (set ExpectedRunnerImage to match)
#
# Tag convention: quokka-runner:${SERVER_VERSION}-${GIT_SHA}.

ARG SERVER_VERSION=dev
ARG GIT_SHA=dev

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
# Embed the expected runner image tag into the binary via ldflags so the
# host worker can fast-fail when versions drift.
RUN GIT_SHA=${GIT_SHA:-dev} SERVER_VERSION=${SERVER_VERSION:-dev} \
    go build -trimpath \
      -ldflags="-s -w -X github.com/diffsec/quokka/internal/worker.ExpectedRunnerImage=quokka-runner:${SERVER_VERSION}-${GIT_SHA}" \
      -o /out/quokka ./cmd/quokka

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/quokka /quokka
USER nonroot:nonroot
ENTRYPOINT ["/quokka", "agent", "run", "--job-file", "/job/spec.json"]
