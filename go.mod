module github.com/bsv8/BitFSCollector

go 1.26.0

require (
	github.com/bsv-blockchain/go-sdk v1.2.18
	github.com/bsv8/BitFSCollectorProtocol v0.1.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.54.0 // indirect
)

// 开发期指向相邻源码；首发版本必须锁定已发布的精确版本并删除本行。
// Development only: first release must pin the published version instead.
replace github.com/bsv8/BitFSCollectorProtocol => ../BitFSCollectorProtocol
