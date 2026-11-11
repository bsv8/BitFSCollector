package disk

import (
	"syscall"
)

// FreeBytes 返回路径所在文件系统的可用字节数。
// FreeBytes reports available bytes on the filesystem holding path.
func FreeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
