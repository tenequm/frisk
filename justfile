set shell := ["bash", "-euo", "pipefail", "-c"]

binary := "frisk"

[private]
default:
    @just --list --unsorted

# Format all Go code
[group('quality')]
fmt:
    golangci-lint fmt ./...

# Check formatting without modifying (CI-safe)
[group('quality')]
fmt-check:
    golangci-lint fmt --diff ./...

# Run linter
[group('quality')]
lint:
    golangci-lint run ./...

# Run linter with auto-fix
[group('quality')]
lint-fix:
    golangci-lint run --fix ./...

# Run all tests with race detection
[group('test')]
test *args="./...":
    gotestsum --format testname -- -race {{ args }}

# Run tests with coverage
[group('test')]
test-cov:
    gotestsum --format testname -- -race -coverprofile=coverage.out -covermode=atomic ./...
    go tool cover -func=coverage.out

# Build the binary
[group('build')]
build:
    go build -o {{ binary }} .

# Tidy and verify modules
[group('deps')]
tidy:
    go mod tidy
    go mod verify

# Full CI gate (format check + lint + test)
[group('ci')]
check: fmt-check lint test
    @echo "All checks passed"

# Clean build artifacts
[group('ci')]
clean:
    go clean
    rm -f {{ binary }} coverage.out
