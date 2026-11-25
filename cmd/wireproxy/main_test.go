package main

import (
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		args []string
		want options
	}{
		{nil, options{}},
		{[]string{"-c", "a.conf"}, options{config: "a.conf"}},
		{[]string{"--config", "a.conf"}, options{config: "a.conf"}},
		{[]string{"--config=a.conf", "-n"}, options{config: "a.conf", configTest: true}},
		{[]string{"-s", "-d", "-c", "a.conf"}, options{config: "a.conf", silent: true, daemon: true}},
		{[]string{"--silent", "--daemon", "--configtest", "--version"}, options{silent: true, daemon: true, configTest: true, version: true}},
		{[]string{"-i", "127.0.0.1:9080", "-v"}, options{info: "127.0.0.1:9080", version: true}},
		{[]string{"--info=127.0.0.1:9080"}, options{info: "127.0.0.1:9080"}},
		{[]string{"-sd", "-c", "a.conf"}, options{config: "a.conf", silent: true, daemon: true}},
		{[]string{"-nsv"}, options{configTest: true, silent: true, version: true}},
		{[]string{"-c", "a.conf", "-sn"}, options{config: "a.conf", silent: true, configTest: true}},
		{[]string{"-ss"}, options{silent: true}},
	}
	for _, tt := range tests {
		got, err := parseArgs(tt.args)
		if err != nil {
			t.Errorf("parseArgs(%q): unexpected error %v", tt.args, err)
			continue
		}
		if *got != tt.want {
			t.Errorf("parseArgs(%q) = %+v, want %+v", tt.args, *got, tt.want)
		}
	}
}

func TestParseArgsErrors(t *testing.T) {
	// parseArgs prints errors and usage to stderr; silence it for the test.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	stderr := os.Stderr
	os.Stderr = devNull
	defer func() { os.Stderr = stderr }()

	for _, args := range [][]string{
		{"--bogus"},
		{"-c"},
		{"extra"},
		{"-c", "a.conf", "extra"},
		{"-sx"},
		{"-snc", "a.conf"},
		{"-sh"},
	} {
		if _, err := parseArgs(args); err == nil || errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseArgs(%q): want a usage error, got %v", args, err)
		}
	}

	for _, args := range [][]string{{"-h"}, {"--help"}} {
		if _, err := parseArgs(args); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("parseArgs(%q): want flag.ErrHelp, got %v", args, err)
		}
	}
}

func TestExpandShortFlags(t *testing.T) {
	tests := []struct {
		in, want []string
	}{
		{[]string{"-sd"}, []string{"-s", "-d"}},
		{[]string{"-s", "-c", "a.conf"}, []string{"-s", "-c", "a.conf"}},
		{[]string{"--config=a.conf", "-nv"}, []string{"--config=a.conf", "-n", "-v"}},
		{[]string{"-sx"}, []string{"-sx"}},
		{[]string{"-snc", "a.conf"}, []string{"-snc", "a.conf"}},
		{[]string{"--sd"}, []string{"--sd"}},
		{[]string{"-sd", "--", "-sd"}, []string{"-s", "-d", "--", "-sd"}},
	}
	for _, tt := range tests {
		got := expandShortFlags(tt.in)
		if strings.Join(got, " ") != strings.Join(tt.want, " ") {
			t.Errorf("expandShortFlags(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
