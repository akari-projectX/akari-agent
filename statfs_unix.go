//go:build unix

package main

import "golang.org/x/sys/unix"

// diskUsage of the filesystem holding path (as df: used = blocks - free).
func diskUsage(path string) (used, total uint64, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, false
	}
	bs := uint64(st.Bsize)         //nolint:unconvert // int64 on linux, uint32 on darwin
	total = uint64(st.Blocks) * bs //nolint:unconvert // uint64 on linux, differs elsewhere
	free := uint64(st.Bfree) * bs  //nolint:unconvert // as above
	if free > total {
		return 0, total, true
	}
	return total - free, total, true
}
