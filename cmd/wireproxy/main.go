package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"

	"github.com/rrampage/wireproxy"
	"golang.zx2c4.com/wireguard/device"
)

// an argument to denote that this process was spawned by -d
const daemonProcess = "daemon-process"

// default paths for wireproxy config file
var default_config_paths = []string{
	"/etc/wireproxy/wireproxy.conf",
	os.Getenv("HOME") + "/.config/wireproxy.conf",
}

var version = "1.1.3"

const usage = `Usage: wireproxy [options]

Userspace wireguard client for proxying

Options:
  -c, --config <path>     Path of configuration file
                          Default paths: /etc/wireproxy/wireproxy.conf, $HOME/.config/wireproxy.conf
  -s, --silent            Silent mode
  -d, --daemon            Make wireproxy run in background
  -i, --info <addr:port>  Specify the address and port for exposing health status
  -v, --version           Print version
  -n, --configtest        Configtest mode. Only check the configuration file for validity.
  -h, --help              Print help information
`

type options struct {
	config     string
	info       string
	silent     bool
	daemon     bool
	version    bool
	configTest bool
}

// boolShortFlags are the single-letter boolean flags that may be grouped.
const boolShortFlags = "sdvn"

// expandShortFlags turns "-sd" into "-s", "-d" when every letter is a
// boolean short flag, matching what argparse accepted. Anything else,
// including groups with an unknown letter or a value option (-sx, -snc), is
// left for flag to handle or reject. Arguments after "--" are untouched.
func expandShortFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for i, a := range args {
		if a == "--" {
			return append(out, args[i:]...)
		}
		if len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.Trim(a[1:], boolShortFlags) == "" {
			for _, c := range a[1:] {
				out = append(out, "-"+string(c))
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// parseArgs parses command-line arguments (without the program name). Each
// option is registered under both its short and long name, so -c, --c,
// -config and --config (with a space or "=" before the value) all work.
// Grouped boolean short flags such as -sd are expanded first.
func parseArgs(args []string) (*options, error) {
	var o options
	fs := flag.NewFlagSet("wireproxy", flag.ContinueOnError)
	fs.Usage = func() { _, _ = fmt.Fprint(fs.Output(), usage) }

	for _, name := range []string{"c", "config"} {
		fs.StringVar(&o.config, name, "", "")
	}
	for _, name := range []string{"i", "info"} {
		fs.StringVar(&o.info, name, "", "")
	}
	for _, f := range []struct {
		names []string
		dst   *bool
	}{
		{[]string{"s", "silent"}, &o.silent},
		{[]string{"d", "daemon"}, &o.daemon},
		{[]string{"v", "version"}, &o.version},
		{[]string{"n", "configtest"}, &o.configTest},
	} {
		for _, name := range f.names {
			fs.BoolVar(f.dst, name, false, "")
		}
	}

	if err := fs.Parse(expandShortFlags(args)); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		err := fmt.Errorf("unexpected arguments: %v", fs.Args())
		_, _ = fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return nil, err
	}
	return &o, nil
}

func panicIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// attempts to pledge and panic if it fails
// this does nothing on non-OpenBSD systems
func pledgeOrPanic(promises string) {
	panicIfError(pledge(promises))
}

// attempts to unveil and panic if it fails
// this does nothing on non-OpenBSD systems
func unveilOrPanic(path string, flags string) {
	panicIfError(unveil(path, flags))
}

// get the executable path via syscalls or infer it from argv
func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return programPath
}

// check if default config file paths exist
func configFilePath() (string, bool) {
	for _, path := range default_config_paths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

// get the file paths for TLS cert and key from the config
func tlsFilePaths(routines []wireproxy.RoutineSpawner) []string {
	var paths []string
	for _, routine := range routines {
		http, ok := routine.(*wireproxy.HTTPConfig)
		if !ok {
			continue
		}
		if http.CertFile != "" {
			paths = append(paths, http.CertFile)
		}
		if http.KeyFile != "" {
			paths = append(paths, http.KeyFile)
		}
	}
	return paths
}

func lock(stage string, roFilles ...string) {
	switch stage {
	case "boot":
		exePath := executablePath()
		// OpenBSD
		unveilOrPanic("/", "r")
		unveilOrPanic(exePath, "x")
		// only allow standard stdio operation, file reading, networking, and exec
		// also remove unveil permission to lock unveil
		pledgeOrPanic("stdio rpath inet dns proc exec")
		// Linux
		panicIfError(landlock.V1.BestEffort().RestrictPaths(
			landlock.RODirs("/"),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
		))
	case "boot-daemon":
	case "read-config":
		// OpenBSD
		pledgeOrPanic("stdio rpath inet dns")
	case "ready":
		// no file access is allowed from now on, only networking
		// OpenBSD
		pledgeOrPanic("stdio inet dns")
		// Linux
		net.DefaultResolver.PreferGo = true // needed to lock down dependencies

		// We need to define the static rules beforehand,
		// so we can add the provided dynamic rules

		rules := []landlock.Rule{
			landlock.ROFiles("/etc/resolv.conf").IgnoreIfMissing(),
			landlock.ROFiles("/dev/fd").IgnoreIfMissing(),
			landlock.ROFiles("/dev/zero").IgnoreIfMissing(),
			landlock.ROFiles("/dev/urandom").IgnoreIfMissing(),
			landlock.ROFiles("/etc/localtime").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/stat").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/status").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/locale").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/cmdline").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/zoneinfo").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/version").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/ngroups_max").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/cap_last_cap").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/vm/overcommit_memory").IgnoreIfMissing(),
			landlock.RWFiles("/dev/log").IgnoreIfMissing(),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
			landlock.RWFiles("/dev/full").IgnoreIfMissing(),
			landlock.RWFiles("/proc/self/fd").IgnoreIfMissing(),
		}

		if len(roFilles) > 0 {
			for _, file := range roFilles {
				rules = append(rules, landlock.ROFiles(file).IgnoreIfMissing())
			}
		}

		panicIfError(landlock.V1.BestEffort().RestrictPaths(rules...))

	default:
		panic("invalid stage")
	}
}

func extractPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	return uint16(port)
}

func lockNetwork(sections []wireproxy.RoutineSpawner, infoAddr *string) {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		rules = append(rules, landlock.BindTCP(extractPort(*infoAddr)))
	}

	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxy.TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *wireproxy.HTTPConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxy.TCPClientTunnelConfig:
			rules = append(rules, landlock.BindTCP(uint16(section.BindAddress.Port)))
		case *wireproxy.Socks5Config:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxy.Socks5TunnelConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxy.SNIConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		}
	}

	panicIfError(landlock.V4.BestEffort().RestrictNet(rules...))
}

func main() {
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGQUIT)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-s
		cancel()
	}()

	exePath := executablePath()
	lock("boot")

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		lock("boot-daemon")
		args = []string{args[0]}
		args = append(args, os.Args[2:]...)
	}
	opts, err := parseArgs(args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	if opts.version {
		fmt.Printf("wireproxy, version %s\n", version)
		return
	}

	if opts.config == "" {
		if path, config_exist := configFilePath(); config_exist {
			opts.config = path
		} else {
			fmt.Println("configuration path is required")
			return
		}
	}

	if !opts.daemon {
		lock("read-config")
	}

	conf, err := wireproxy.ParseConfig(opts.config)
	if err != nil {
		log.Fatal(err)
	}

	if opts.configTest {
		fmt.Println("Config OK")
		return
	}

	lockNetwork(conf.Routines, &opts.info)

	if isDaemonProcess {
		os.Stdout, _ = os.Open(os.DevNull)
		os.Stderr, _ = os.Open(os.DevNull)
		opts.daemon = false
	}

	if opts.daemon {
		args[0] = daemonProcess
		cmd := exec.Command(exePath, args...)
		err = cmd.Start()
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	// Wireguard doesn't allow configuring which FD to use for logging
	// https://github.com/WireGuard/wireguard-go/blob/master/device/logger.go#L39
	// so redirect STDOUT to STDERR, we don't want to print anything to STDOUT anyways
	os.Stdout = os.Stderr
	logLevel := device.LogLevelVerbose
	if opts.silent {
		logLevel = device.LogLevelSilent
	}

	lock("ready", tlsFilePaths(conf.Routines)...)

	tun, err := wireproxy.StartWireguard(conf, logLevel)
	if err != nil {
		log.Fatal(err)
	}

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tun)
	}

	tun.StartPingIPs()

	if opts.info != "" {
		go func() {
			err := http.ListenAndServe(opts.info, tun)
			if err != nil {
				panic(err)
			}
		}()
	}

	<-ctx.Done()
}
