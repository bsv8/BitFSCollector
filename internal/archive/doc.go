// Package archive 实现接收归档：流式收 gzip 原始字节、验签、原样落盘。
// 不解压、不检查内部字段、不建立文件索引、不去重。
package archive
