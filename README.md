# BitFSCollector

采集接收服务：使用 Go SDK（`BitFSCollectorProtocol`）接收请求、验签，将 gzip 和签名原样归档。只验证提交签名并归档，不解压、不解析文件元数据、不去重。

BitFSCollector is the receiver: verify with the Go SDK and archive the exact bytes. No decompression, no metadata indexing, no dedup.

- 有效需求与验收在工程仓：`docs/BitFSCollector/`、`e2e/BitFSCollector/`、`ops/BitFSCollector/`
- 归档布局：`<归档根>/YYYY/MM/DD/<公钥>-<唯一编号>.gzip`＋同名 `.sig`

## 运行

```sh
go build -o bitfs-collector ./cmd/bitfs-collector
./bitfs-collector -config config.json
```

配置见 `ops/BitFSCollector/config.example.json`（工程仓）：监听地址、归档根目录、请求体上限、并发上限。TLS 在反代终止，本服务只提供 HTTP。

## 测试

```sh
go test ./...
```
