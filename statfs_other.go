//go:build !unix

package main

func diskUsage(string) (used, total uint64, ok bool) { return 0, 0, false }
