package wireproxy

import (
	"net/netip"
	"testing"
)

func TestCreateIPCRequest(t *testing.T) {
	ep := "1.2.3.4:51820"
	lp := 1234
	conf := &DeviceConfig{SecretKey: "aa", ListenPort: &lp, Peers: []PeerConfig{
		{PublicKey: "bb", KeepAlive: 25, PreSharedKey: "cc", Endpoint: &ep, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{PublicKey: "dd", KeepAlive: 0, PreSharedKey: "ee"},
	}}

	setting, err := CreateIPCRequest(conf)
	if err != nil {
		t.Fatal(err)
	}

	want := "private_key=aa\n" +
		"listen_port=1234\n" +
		"public_key=bb\n" +
		"persistent_keepalive_interval=25\n" +
		"preshared_key=cc\n" +
		"endpoint=1.2.3.4:51820\n" +
		"allowed_ip=10.0.0.0/8\n" +
		"public_key=dd\n" +
		"persistent_keepalive_interval=0\n" +
		"preshared_key=ee\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"allowed_ip=::0/0\n"
	if setting.IpcRequest != want {
		t.Fatalf("IpcRequest mismatch\n got: %q\nwant: %q", setting.IpcRequest, want)
	}
}
