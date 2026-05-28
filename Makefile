# quokka build targets.
#
# Common: SERVER_VERSION + GIT_SHA derive the runner image tag, which is
# also embedded into the binary via -ldflags so the worker can fail-fast on
# version drift.

SERVER_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_SHA        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
RUNNER_TAG     ?= quokka-runner:$(SERVER_VERSION)-$(GIT_SHA)

LDFLAGS = -s -w -X github.com/diffsec/quokka/internal/worker.ExpectedRunnerImage=$(RUNNER_TAG)

.PHONY: build runner-image server-image test

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o quokka ./cmd/quokka

runner-image:
	docker build \
	  --build-arg SERVER_VERSION=$(SERVER_VERSION) \
	  --build-arg GIT_SHA=$(GIT_SHA) \
	  -t $(RUNNER_TAG) \
	  -f build/runner-image/Dockerfile .

server-image:
	docker build -t quokka:$(SERVER_VERSION) -f Dockerfile .

test:
	go test -short ./...
