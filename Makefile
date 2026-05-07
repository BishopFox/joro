.PHONY: build build-frontend build-all clean dev

BINARY  := joro
DIST    := dist
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.commit=$(COMMIT)

build-frontend:
	cd web && npm install && npm run build

build: build-frontend
	go build -ldflags="$(LDFLAGS)" -o $(BINARY) .

build-all: build-frontend
	GOOS=linux  GOARCH=amd64  go build -ldflags="$(LDFLAGS)" -o $(DIST)/joro-linux-amd64 .
	GOOS=darwin GOARCH=arm64  go build -ldflags="$(LDFLAGS)" -o $(DIST)/joro-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/joro-windows-amd64.exe .

# Start the backend with --dev so it proxies UI requests to Vite.
# Run `cd web && npm run dev` in another terminal first.
dev:
	go run . --dev

clean:
	rm -f $(BINARY) $(DIST)/joro-*
	rm -rf web/dist web/node_modules
