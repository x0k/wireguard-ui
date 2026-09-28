package util

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ngoduykhanh/wireguard-ui/model"
)

func TestBuildClientConfigOmitsAmneziaWGPropertiesWhenEmpty(t *testing.T) {
	config := BuildClientConfig(testClient(), testServer(model.AmneziaWGProperties{}), testGlobalSetting(""))

	for _, property := range []string{"Jc =", "Jmin =", "Jmax =", "S1 =", "H1 =", "I1 ="} {
		if strings.Contains(config, property) {
			t.Fatalf("expected config to omit %q, got:\n%s", property, config)
		}
	}
}

func TestBuildClientConfigIncludesAmneziaWGProperties(t *testing.T) {
	config := BuildClientConfig(testClient(), testServer(model.AmneziaWGProperties{
		Jc:   4,
		Jmin: 16,
		Jmax: 64,
		S1:   11,
		S2:   22,
		S3:   33,
		S4:   44,
		H1:   "123-456",
		H2:   "223-456",
		H3:   "323-456",
		H4:   "423-456",
		I1:   "<r 10>",
	}), testGlobalSetting(""))

	wantLines := []string{
		"PrivateKey = client-private",
		"Jc = 4",
		"Jmin = 16",
		"Jmax = 64",
		"S1 = 11",
		"S2 = 22",
		"S3 = 33",
		"S4 = 44",
		"H1 = 123-456",
		"H2 = 223-456",
		"H3 = 323-456",
		"H4 = 423-456",
		"I1 = <r 10>",
		"DNS = 1.1.1.1",
	}

	for _, line := range wantLines {
		if !strings.Contains(config, line) {
			t.Fatalf("expected config to include %q, got:\n%s", line, config)
		}
	}
}

func TestBuildClientConfigIncludesAmneziaWG31ClientProperties(t *testing.T) {
	config := BuildClientConfig(testClient(), testServer(model.AmneziaWGProperties{
		S1:                     15,
		S2:                     15,
		S3:                     15,
		S4:                     15,
		ContentPaddingAddition: "0-10",
		RekeyAfterTime:         "120",
		RekeyTimeout:           "5",
		RejectAfterTime:        "180-200",
		KeepaliveTimeout:       "10",
		MaxHandshakeAttempts:   "0-3",
	}), testGlobalSetting(""))

	for _, line := range []string{
		"ContentPaddingAddition = 0-10",
		"RekeyAfterTime = 120",
		"RekeyTimeout = 5",
		"RejectAfterTime = 180-200",
		"KeepaliveTimeout = 10",
		"MaxHandshakeAttempts = 0-3",
	} {
		if !strings.Contains(config, line) {
			t.Fatalf("expected client config to include %q, got:\n%s", line, config)
		}
	}
}

// The header protection key is a server secret. A client that receives it can
// forge protected handshake headers, so it must never appear in a client config.
// The header protection key is a shared secret, not a server-only one: both
// ends XOR the same keystream over the start of every packet, so a client
// without it cannot classify incoming packets. The responder-only booleans must
// stay out of the client config.
func TestBuildClientConfigSharesHeaderProtectionKeyButNotServerBooleans(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	props := model.AmneziaWGProperties{
		S1: 12, S2: 12, S3: 12, S4: 12,
		HeaderProtectionKey: key,
		RandomTrailers:      true,
		DisableCookies:      true,
	}
	config := BuildClientConfig(testClient(), testServer(props), testGlobalSetting(""))

	if !strings.Contains(config, "HeaderProtectionKey = "+key) {
		t.Fatalf("client config must carry the header protection key, got:\n%s", config)
	}
	for _, leaked := range []string{"RandomTrailers", "DisableCookies"} {
		if strings.Contains(config, leaked) {
			t.Fatalf("expected client config to omit %q, got:\n%s", leaked, config)
		}
	}
}

func TestBuildServerAmneziaWGProperties(t *testing.T) {
	props := model.AmneziaWGProperties{
		S1: 12, S2: 12, S3: 12, S4: 12,
		HeaderProtectionKey: "c2VjcmV0a2V5",
		RandomTrailers:      true,
		DisableCookies:      true,
		RekeyAfterTime:      "120",
	}
	got := BuildServerAmneziaWGProperties(props)

	for _, line := range []string{
		"HeaderProtectionKey = c2VjcmV0a2V5",
		"RandomTrailers = on",
		"DisableCookies = on",
		"S4 = 12",
	} {
		if !strings.Contains(got, line) {
			t.Fatalf("expected server properties to include %q, got:\n%s", line, got)
		}
	}

	// The client-only timing knobs are not part of the server interface.
	if strings.Contains(got, "RekeyAfterTime") {
		t.Fatalf("expected server properties to omit RekeyAfterTime, got:\n%s", got)
	}
}

func TestBuildAmneziaWGPropertiesIsSupersetOfLegacyOutput(t *testing.T) {
	// This is the exact property set wireguard-ui supported before AmneziaWG
	// 3.1, i.e. everything the old BuildAmneziaWGProperties wrote. Custom
	// wg.conf templates call that function, so its output must never shrink.
	props := model.AmneziaWGProperties{
		Jc:   4,
		Jmin: 16,
		Jmax: 64,
		S1:   11,
		S2:   22,
		S3:   33,
		S4:   44,
		H1:   "123-456",
		H2:   "223-456",
		H3:   "323-456",
		H4:   "423-456",
		I1:   "<r 10>",
		I2:   "<b 20>",
		I3:   "<c 30>",
		I4:   "<d 40>",
		I5:   "<e 50>",
	}

	const want = "Jc = 4\n" +
		"Jmin = 16\n" +
		"Jmax = 64\n" +
		"S1 = 11\n" +
		"S2 = 22\n" +
		"S3 = 33\n" +
		"S4 = 44\n" +
		"H1 = 123-456\n" +
		"H2 = 223-456\n" +
		"H3 = 323-456\n" +
		"H4 = 423-456\n" +
		"I1 = <r 10>\n" +
		"I2 = <b 20>\n" +
		"I3 = <c 30>\n" +
		"I4 = <d 40>\n" +
		"I5 = <e 50>\n"

	if got := BuildAmneziaWGProperties(props); got != want {
		t.Fatalf("legacy output changed:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestBuildAmneziaWGPropertiesIncludesAllAmneziaWG31Properties(t *testing.T) {
	got := BuildAmneziaWGProperties(model.AmneziaWGProperties{
		S1:                     12,
		S2:                     12,
		S3:                     12,
		S4:                     12,
		HeaderProtectionKey:    "c2VjcmV0a2V5",
		RandomTrailers:         true,
		DisableCookies:         true,
		ContentPaddingAddition: "0-10",
		RekeyAfterTime:         "120",
		RekeyTimeout:           "5",
		RejectAfterTime:        "180-200",
		KeepaliveTimeout:       "10",
		MaxHandshakeAttempts:   "0-3",
	})

	for _, line := range []string{
		"HeaderProtectionKey = c2VjcmV0a2V5",
		"RandomTrailers = on",
		"DisableCookies = on",
		"ContentPaddingAddition = 0-10",
		"RekeyAfterTime = 120",
		"RekeyTimeout = 5",
		"RejectAfterTime = 180-200",
		"KeepaliveTimeout = 10",
		"MaxHandshakeAttempts = 0-3",
	} {
		if !strings.Contains(got, line) {
			t.Fatalf("expected legacy builder to include %q, got:\n%s", line, got)
		}
	}
}

func TestBuildServerAmneziaWGPropertiesOmitsUnsetBooleans(t *testing.T) {
	got := BuildServerAmneziaWGProperties(model.AmneziaWGProperties{S1: 15})

	if strings.Contains(got, "RandomTrailers") || strings.Contains(got, "DisableCookies") {
		t.Fatalf("expected unset booleans to be omitted, got:\n%s", got)
	}
}

func TestValidateAmneziaWGProperties(t *testing.T) {
	tests := []struct {
		name    string
		props   model.AmneziaWGProperties
		wantErr bool
	}{
		{
			name:  "empty is valid",
			props: model.AmneziaWGProperties{},
		},
		{
			name:  "valid junk range",
			props: model.AmneziaWGProperties{Jc: 128, Jmin: 1, Jmax: 1279},
		},
		{
			name:    "jc above max",
			props:   model.AmneziaWGProperties{Jc: 129},
			wantErr: true,
		},
		{
			name:    "jmin must be less than jmax",
			props:   model.AmneziaWGProperties{Jmin: 64, Jmax: 64},
			wantErr: true,
		},
		{
			name:    "jmax below 1280",
			props:   model.AmneziaWGProperties{Jmin: 1, Jmax: 1280},
			wantErr: true,
		},
		{
			name:    "negative values are invalid",
			props:   model.AmneziaWGProperties{S1: -1},
			wantErr: true,
		},
		{
			name: "valid 3.1 ranges",
			props: model.AmneziaWGProperties{
				ContentPaddingAddition: "0",
				RekeyAfterTime:         "120-150",
				RekeyTimeout:           "5",
				RejectAfterTime:        "0",
				KeepaliveTimeout:       "10-20",
				MaxHandshakeAttempts:   "0-3",
			},
		},
		{
			name:    "range is not a number",
			props:   model.AmneziaWGProperties{RekeyAfterTime: "abc"},
			wantErr: true,
		},
		{
			name:    "range with too many bounds",
			props:   model.AmneziaWGProperties{RekeyAfterTime: "1-2-3"},
			wantErr: true,
		},
		{
			name:    "range above u16",
			props:   model.AmneziaWGProperties{RekeyAfterTime: "65536"},
			wantErr: true,
		},
		{
			name:    "range lower bound above upper bound",
			props:   model.AmneziaWGProperties{KeepaliveTimeout: "20-10"},
			wantErr: true,
		},
		{
			name: "valid header protection key",
			props: model.AmneziaWGProperties{
				S1: 12, S2: 12, S3: 12, S4: 12,
				HeaderProtectionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
		},
		{
			name: "header protection key requires s padding of at least 12",
			props: model.AmneziaWGProperties{
				S1: 15, S2: 15, S3: 15, S4: 11,
				HeaderProtectionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
			wantErr: true,
		},
		{
			name: "header protection key must be 32 bytes",
			props: model.AmneziaWGProperties{
				S1: 12, S2: 12, S3: 12, S4: 12,
				HeaderProtectionKey: base64.StdEncoding.EncodeToString(make([]byte, 16)),
			},
			wantErr: true,
		},
		{
			name: "header protection key must be base64",
			props: model.AmneziaWGProperties{
				S1: 12, S2: 12, S3: 12, S4: 12,
				HeaderProtectionKey: "not base64 at all!!",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAmneziaWGProperties(tt.props)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAmneziaWGProperties() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteWireGuardServerConfigIncludesAmneziaWGProperties(t *testing.T) {
	configFile, err := os.CreateTemp(t.TempDir(), "wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	configFile.Close()

	server := testServer(model.AmneziaWGProperties{Jc: 4, Jmin: 16, Jmax: 64, S1: 11, H1: "123-456"})
	client := testClient()
	client.Enabled = true

	err = WriteWireGuardServerConfig(fstest.MapFS{
		"wg.conf": {Data: []byte(`# test template
[Interface]
Address = {{$first :=true}}{{range .serverConfig.Interface.Addresses }}{{if $first}}{{$first = false}}{{else}},{{end}}{{.}}{{end}}
ListenPort = {{ .serverConfig.Interface.ListenPort }}
PrivateKey = {{ .serverConfig.KeyPair.PrivateKey }}
{{BuildServerAmneziaWGProperties .serverConfig.Interface.AmneziaWGProperties -}}
{{range .clientDataList}}{{if eq .Client.Enabled true}}
[Peer]
PublicKey = {{ .Client.PublicKey }}
{{end}}{{end}}
`)},
	}, server, []model.ClientData{{Client: &client}}, nil, testGlobalSetting(configFile.Name()))
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(configFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)

	for _, line := range []string{"Jc = 4", "Jmin = 16", "Jmax = 64", "S1 = 11", "H1 = 123-456"} {
		if !strings.Contains(config, line) {
			t.Fatalf("expected server config to include %q, got:\n%s", line, config)
		}
	}
}

// The server config is the one place the header protection key belongs, and
// the custom template path must keep that behaviour.
func TestWriteWireGuardServerConfigIncludesServerOnlyProperties(t *testing.T) {
	configFile, err := os.CreateTemp(t.TempDir(), "wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	configFile.Close()

	const key = "c2VjcmV0a2V5"
	server := testServer(model.AmneziaWGProperties{
		S1: 12, S2: 12, S3: 12, S4: 12,
		HeaderProtectionKey: key,
		RandomTrailers:      true,
		DisableCookies:      true,
		RekeyAfterTime:      "120",
	})

	err = WriteWireGuardServerConfig(fstest.MapFS{
		"wg.conf": {Data: []byte(`[Interface]
{{BuildServerAmneziaWGProperties .serverConfig.Interface.AmneziaWGProperties -}}
`)},
	}, server, nil, nil, testGlobalSetting(configFile.Name()))
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(configFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)

	for _, line := range []string{"HeaderProtectionKey = " + key, "RandomTrailers = on", "DisableCookies = on"} {
		if !strings.Contains(config, line) {
			t.Fatalf("expected server config to include %q, got:\n%s", line, config)
		}
	}
	if strings.Contains(config, "RekeyAfterTime") {
		t.Fatalf("expected server config to omit client-only RekeyAfterTime, got:\n%s", config)
	}
}

// A custom wg.conf template written before AmneziaWG 3.1 support calls
// BuildAmneziaWGProperties. That path must keep emitting the server-only
// properties, otherwise the tunnel comes up with header protection silently
// disabled and nothing in the UI reports an error.
func TestWriteWireGuardServerConfigCustomTemplateLegacyBuilderKeepsServerProperties(t *testing.T) {
	configFile, err := os.CreateTemp(t.TempDir(), "wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	configFile.Close()

	const key = "c2VjcmV0a2V5"
	server := testServer(model.AmneziaWGProperties{
		Jc:                  4,
		Jmin:                16,
		Jmax:                64,
		S1:                  12,
		S2:                  12,
		S3:                  12,
		S4:                  12,
		HeaderProtectionKey: key,
		RandomTrailers:      true,
		DisableCookies:      true,
	})

	err = WriteWireGuardServerConfig(fstest.MapFS{
		"wg.conf": {Data: []byte(`[Interface]
{{BuildAmneziaWGProperties .serverConfig.Interface.AmneziaWGProperties -}}
`)},
	}, server, nil, nil, testGlobalSetting(configFile.Name()))
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(configFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)

	for _, line := range []string{
		"Jc = 4",
		"S4 = 12",
		"HeaderProtectionKey = " + key,
		"RandomTrailers = on",
		"DisableCookies = on",
	} {
		if !strings.Contains(config, line) {
			t.Fatalf("expected legacy custom template output to include %q, got:\n%s", line, config)
		}
	}
}

// The container builds awg from the pinned amneziawg-tools submodule. If the
// UI writes an option that parser does not know, awg-quick refuses to load the
// config and the tunnel comes up with no error visible in the UI. This test
// keeps the two lists in sync.
func TestAmneziaWGOptionsAreKnownToBundledTools(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "amneziawg-tools", "src", "config.c"))
	if err != nil {
		t.Skipf("bundled amneziawg-tools not available: %v", err)
	}

	known := map[string]bool{}
	for _, line := range strings.Split(string(source), "\n") {
		_, rest, found := strings.Cut(line, `key_match("`)
		if !found {
			continue
		}
		if name, _, closed := strings.Cut(rest, `"`); closed {
			known[name] = true
		}
	}

	props := model.AmneziaWGProperties{
		Jc: 5, Jmin: 40, Jmax: 70, S1: 15, S2: 15, S3: 15, S4: 15,
		H1: "1", H2: "2", H3: "3", H4: "4",
		I1: "<r 32>", I2: "<r 8>", I3: "<r 8>", I4: "<r 8>", I5: "<r 8>",
		HeaderProtectionKey:    "c2VjcmV0",
		RandomTrailers:         true,
		DisableCookies:         true,
		ContentPaddingAddition: "0-10",
		RekeyAfterTime:         "120",
		RekeyTimeout:           "5",
		RejectAfterTime:        "180",
		KeepaliveTimeout:       "10",
		MaxHandshakeAttempts:   "3",
	}

	for _, config := range []string{
		BuildServerAmneziaWGProperties(props),
		BuildClientAmneziaWGProperties(props),
	} {
		for _, line := range strings.Split(strings.TrimSpace(config), "\n") {
			name, _, _ := strings.Cut(line, "=")
			name = strings.TrimSpace(name)
			if !known[name] {
				t.Errorf("bundled awg does not support option %q (from line %q)", name, line)
			}
		}
	}
}

func testClient() model.Client {
	return model.Client{
		ID:           "client-id",
		PrivateKey:   "client-private",
		PublicKey:    "client-public",
		AllocatedIPs: []string{"10.0.0.2/32"},
		AllowedIPs:   []string{"0.0.0.0/0"},
		UseServerDNS: true,
		CreatedAt:    time.Unix(0, 0).UTC(),
		UpdatedAt:    time.Unix(0, 0).UTC(),
	}
}

func testServer(props model.AmneziaWGProperties) model.Server {
	return model.Server{
		KeyPair: &model.ServerKeypair{
			PrivateKey: "server-private",
			PublicKey:  "server-public",
		},
		Interface: &model.ServerInterface{
			Addresses:           []string{"10.0.0.1/24"},
			ListenPort:          51820,
			AmneziaWGProperties: props,
		},
	}
}

func testGlobalSetting(configFilePath string) model.GlobalSetting {
	return model.GlobalSetting{
		EndpointAddress:     "vpn.example.com",
		DNSServers:          []string{"1.1.1.1"},
		MTU:                 1420,
		PersistentKeepalive: 15,
		ConfigFilePath:      configFilePath,
	}
}
