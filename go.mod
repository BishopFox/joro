module github.com/BishopFox/joro

go 1.25.0

require github.com/hashicorp/go-uuid v1.0.3

require (
	github.com/BishopFox/joro/sdk v0.0.0-00010101000000-000000000000
	github.com/gorilla/websocket v1.5.3
	github.com/miekg/dns v1.1.72
	github.com/spf13/pflag v1.0.10
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.45.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
	modernc.org/sqlite v1.46.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/BishopFox/joro/sdk => ./sdk
