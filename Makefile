.PHONY: build test lint fmt tidy run e2e vuln
# Static (no libc, runs in scratch/distroless) and reproducible (no local paths).
build:
	CGO_ENABLED=0 go build -trimpath -o ./bin/scep-intune ./cmd/scep-intune
test:
	go test ./...
lint:
	golangci-lint run
fmt:
	golangci-lint fmt
tidy:
	go mod tidy
# Known vulnerabilities reachable from the code (same pinned version as CI).
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
run: build
	./bin/scep-intune -config config.example.yaml
# Full SCEP enrollment through step-ca, the bridge and the Intune mock (linux/amd64).
e2e:
	bash test/e2e/run.sh
