# tbox build.
#
# sing-box REALITY requires the `with_utls` build tag, and a Go toolchain
# >= 1.24.7 (set GO to your toolchain if `go` on PATH is older).

GO ?= go
TAGS := with_utls
BIN := bin/tbox

.PHONY: build test vet tidy clean run-server run-client

build:
	$(GO) build -tags '$(TAGS)' -o $(BIN) ./cmd/tbox

test:
	$(GO) test -tags '$(TAGS)' ./...

# End-to-end test makes a real REALITY handshake to www.microsoft.com:443
# (needs outbound internet).
test-e2e:
	$(GO) test -tags '$(TAGS)' -v -run TestEndToEnd ./internal/integration/

vet:
	$(GO) vet -tags '$(TAGS)' ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin
