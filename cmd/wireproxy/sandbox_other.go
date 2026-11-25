//go:build !openbsd

package main

// pledge(2) and unveil(2) only exist on OpenBSD; elsewhere these are no-ops.

func pledge(string) error { return nil }

func unveil(string, string) error { return nil }
