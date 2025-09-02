GO ?= go
PKGS := ./...
COVERPKG := ./...

.PHONY: tidy lint test test-race cover
tidy:
	$(GO) mod tidy

lint:
	golangci-lint run

test:
	$(GO) test -count=1 $(PKGS)

test-race:
	$(GO) test -count=1 -race $(PKGS)

cover:
	$(GO) test -count=1 -race -covermode=atomic -coverpkg=$(COVERPKG) -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -1
