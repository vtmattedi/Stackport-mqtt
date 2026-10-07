package docs

import (
	"strings"
	"testing"
)

func TestGenericDocsNameNoDeployment(t *testing.T) {
	for _, lang := range []string{"en", "pt"} {
		doc, ok := Get("v1", lang, Vars{})
		if !ok {
			t.Fatal(lang)
		}
		low := strings.ToLower(doc.Documentation)
		for _, bad := range []string{"nightmare", "mattediworks", "nmnw", "{{", "<!--"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s docs contain %q", lang, bad)
			}
		}
		if strings.Contains(low, "websocket") {
			t.Errorf("%s docs mention WebSocket without a URL", lang)
		}
	}
}

func TestVarsAreSubstituted(t *testing.T) {
	v := Vars{Host: "broker.example.org", Port: "8884", WSURL: "wss://ws.example.org/mqtt", CAFile: "my-ca.crt"}
	doc, _ := Get("v1", "en", v)
	for _, want := range []string{"broker.example.org", "8884", "wss://ws.example.org/mqtt", "my-ca.crt"} {
		if !strings.Contains(doc.Documentation, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(doc.Documentation, "{{") || strings.Contains(doc.Documentation, "<!--") {
		t.Error("placeholder or marker left behind")
	}
}

func TestProfile(t *testing.T) {
	doc, _ := Get("v1", "pt", Vars{Host: "h.example", Profile: "nightmare"})
	if !strings.Contains(doc.Documentation, "Perfil NightMare") || !strings.Contains(doc.Documentation, `"h.example"`) {
		t.Error("profile not appended or not rendered")
	}
	for _, p := range []string{"missing", "../v1.en", "NIGHTMARE/x", ""} {
		d, _ := Get("v1", "en", Vars{Profile: p})
		if strings.Contains(d.Documentation, "NightMare") {
			t.Errorf("profile %q applied", p)
		}
	}
}
