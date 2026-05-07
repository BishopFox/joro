.PHONY: build build-frontend build-all release-snapshot clean dev

BINARY  := joro
DIST    := dist
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.commit=$(COMMIT)
CC_WRAP := $(CURDIR)/scripts/cc.sh
# netgo + osusergo avoid libresolv/libc linkage — required for zig cc cross-builds.
TAGS    := netgo,osusergo

build-frontend:
	cd web && npm install && npm run build

# Native build. CGO_ENABLED defaults to 1 on the host, which is required for
# Go's plugin package (dlopen-based). Do not flip this off.
build: build-frontend
	go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(BINARY) .

# Cross-compile to all 6 release targets via zig cc (wrapped by scripts/cc.sh).
# Matches .goreleaser.yaml so dev cross-builds are plugin-capable too.
# Requires `zig` on PATH (brew install zig).
build-all: build-frontend
	@command -v zig >/dev/null || { echo 'zig not found on PATH (brew install zig)'; exit 1; }
	CGO_ENABLED=1 CC="$(CC_WRAP) x86_64-linux-gnu.2.17"  GOOS=linux   GOARCH=amd64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(DIST)/joro-linux-amd64       .
	CGO_ENABLED=1 CC="$(CC_WRAP) aarch64-linux-gnu.2.17" GOOS=linux   GOARCH=arm64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(DIST)/joro-linux-arm64       .
	CGO_ENABLED=1                                        GOOS=darwin  GOARCH=amd64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(DIST)/joro-darwin-amd64      .
	CGO_ENABLED=1                                        GOOS=darwin  GOARCH=arm64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(DIST)/joro-darwin-arm64      .
	CGO_ENABLED=1 CC="$(CC_WRAP) x86_64-windows-gnu"     GOOS=windows GOARCH=amd64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(DIST)/joro-windows-amd64.exe .
	CGO_ENABLED=1 CC="$(CC_WRAP) aarch64-windows-gnu"    GOOS=windows GOARCH=arm64 go build -tags="$(TAGS)" -ldflags="$(LDFLAGS)" -o $(DIST)/joro-windows-arm64.exe .

# Local snapshot release for sanity-checking goreleaser config without tagging.
release-snapshot:
	goreleaser release --snapshot --clean

# Start the backend with --dev so it proxies UI requests to Vite.
# Run `cd web && npm run dev` in another terminal first.
dev:
	go run . --dev

clean:
	rm -f $(BINARY) $(DIST)/joro-*
	rm -rf web/dist web/node_modules
