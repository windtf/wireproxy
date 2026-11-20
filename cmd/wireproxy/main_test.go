package main

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/windtf/wireproxy"
	"golang.zx2c4.com/wireguard/device"
)

func TestLogLevels(t *testing.T) {
	tests := []struct {
		level      string
		silent     bool
		wantApp    wireproxy.LogLevel
		wantDevice int
	}{
		{"error", false, wireproxy.LogError, device.LogLevelError},
		{"info", false, wireproxy.LogInfo, device.LogLevelError},
		{"debug", false, wireproxy.LogDebug, device.LogLevelVerbose},
		{"info", true, wireproxy.LogError, device.LogLevelError},
		{"debug", true, wireproxy.LogError, device.LogLevelError},
	}

	for _, tt := range tests {
		app, dev := logLevels(tt.level, tt.silent)
		if app != tt.wantApp || dev != tt.wantDevice {
			t.Errorf("logLevels(%q, %v) = %d, %d; want %d, %d", tt.level, tt.silent, app, dev, tt.wantApp, tt.wantDevice)
		}
	}
}

// TestHelperMain runs main() in a child process with the arguments in
// WIREPROXY_TEST_ARGS, so tests can observe its exit status and output.
func TestHelperMain(t *testing.T) {
	args, ok := os.LookupEnv("WIREPROXY_TEST_ARGS")
	if !ok {
		t.Skip("helper process only")
	}
	os.Args = append([]string{"wireproxy"}, strings.Fields(args)...)
	main()
	os.Exit(0)
}

func runMain(t *testing.T, args string, env ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$")
	cmd.Env = append(append(os.Environ(), "WIREPROXY_TEST_ARGS="+args), env...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errOut.String()
}

func TestUsageErrorExitsNonZero(t *testing.T) {
	for _, args := range []string{"--bogus", "-i", "--log-level loud"} {
		code, stdout, stderr := runMain(t, args)
		if code != 2 {
			t.Errorf("%q: exit code = %d, want 2", args, code)
		}
		if !strings.Contains(stderr, "usage: wireproxy") {
			t.Errorf("%q: usage not printed to stderr: %q", args, stderr)
		}
		if strings.Contains(stdout, "usage: wireproxy") {
			t.Errorf("%q: usage printed to stdout: %q", args, stdout)
		}
	}
}

const testConfig = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820
`

func writeTestConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wireproxy.conf")
	if err := os.WriteFile(path, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freeAddr returns a loopback address that was free a moment ago. The caller
// must tolerate another process taking it before use.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// startChild starts main() in a child process and returns once its health
// endpoint answers, which happens after the signal handler is installed. ok is
// false if the child exited first, for example because another process took
// the port between freeAddr and the child's bind.
func startChild(t *testing.T, path, addr string) (cmd *exec.Cmd, done chan error, stderr *bytes.Buffer, ok bool) {
	t.Helper()
	cmd = exec.Command(os.Args[0], "-test.run=^TestHelperMain$")
	cmd.Env = append(os.Environ(), "WIREPROXY_TEST_ARGS=-s -c "+path+" -i "+addr)
	stderr = &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	done = make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-done:
			done <- err
			return cmd, done, stderr, false
		default:
		}
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			return cmd, done, stderr, true
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("child never became ready: %v\n%s", err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSIGTERMShutsDownCleanly(t *testing.T) {
	path := writeTestConfig(t)

	var (
		cmd    *exec.Cmd
		done   chan error
		stderr *bytes.Buffer
		ok     bool
	)
	for attempt := 0; attempt < 3 && !ok; attempt++ {
		cmd, done, stderr, ok = startChild(t, path, freeAddr(t))
	}
	if !ok {
		t.Fatalf("child never started: %s", stderr.String())
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("child did not exit cleanly on SIGTERM: %v\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit after SIGTERM")
	}
}

func TestHelpExitsZero(t *testing.T) {
	code, stdout, _ := runMain(t, "--help")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "usage: wireproxy") {
		t.Errorf("help not printed to stdout: %q", stdout)
	}
}

func TestMissingConfigIsUsageError(t *testing.T) {
	// An empty HOME hides any default config under $HOME/.config.
	code, stdout, stderr := runMain(t, "", "HOME="+t.TempDir())
	if _, err := os.Stat("/etc/wireproxy/wireproxy.conf"); err == nil {
		t.Skip("a default config exists on this machine")
	}
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "configuration path is required") || !strings.Contains(stderr, "usage: wireproxy") {
		t.Errorf("stderr = %q", stderr)
	}
	if stdout != "" {
		t.Errorf("unexpected stdout: %q", stdout)
	}
}

func TestUnreadableConfigExitsOne(t *testing.T) {
	code, _, stderr := runMain(t, "-c "+filepath.Join(t.TempDir(), "missing.conf"))
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestInfoListenFailureExitsOne(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	code, _, stderr := runMain(t, "-c "+writeTestConfig(t)+" -i "+l.Addr().String())
	if code != 1 {
		t.Errorf("exit code = %d, want 1\n%s", code, stderr)
	}
	if strings.Contains(stderr, "goroutine ") {
		t.Errorf("stack trace printed: %s", stderr)
	}
}
