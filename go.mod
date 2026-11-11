module github.com/bsv8/BitFSCollector

go 1.26.0

require (
	github.com/bsv-blockchain/go-sdk v1.2.18
	github.com/bsv8/BitFSCollectorProtocol v0.1.0
	modernc.org/sqlite v1.62.0
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// 开发期指向相邻源码；首发版本必须锁定已发布的精确版本并删除本行。
// Development only: first release must pin the published version instead.
replace github.com/bsv8/BitFSCollectorProtocol => ../BitFSCollectorProtocol
