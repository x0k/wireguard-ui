package util

import (
	"os"
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
{{BuildAmneziaWGProperties .serverConfig.Interface.AmneziaWGProperties -}}
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
