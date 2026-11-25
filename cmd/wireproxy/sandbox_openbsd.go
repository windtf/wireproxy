//go:build openbsd

package main

import "golang.org/x/sys/unix"

func pledge(promises string) error {
	return unix.PledgePromises(promises)
}

func unveil(path string, flags string) error {
	return unix.Unveil(path, flags)
}
