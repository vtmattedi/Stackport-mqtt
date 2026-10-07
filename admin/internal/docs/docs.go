// Package docs serves the MQTT service documentation embedded in the binary, in the
// shape the control plane's Documentation pages expect. Content is written once per
// language; an unknown or missing language falls back to English.
package docs

import (
	"embed"
	"regexp"
	"strings"
)

//go:embed content/*.md content/profiles/*.md
var content embed.FS

// Vars fills the deployment-specific values of the generic documentation. Empty fields
// fall back to neutral placeholders, so the text is never wrong, only less specific.
type Vars struct {
	Host   string // public broker host name
	Port   string // public TLS port, "8883" when empty
	WSURL  string // WebSocket URL; the browser section is dropped when empty
	CAFile string // file name of the CA certificate clients trust
	// Profile optionally appends a deployment-specific section (profiles/<name>.<lang>.md).
	// An unknown or malformed name is ignored.
	Profile string
}

var profilePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

var wsBlock = regexp.MustCompile(`(?s)<!--ws-->(.*?)<!--/ws-->\n*`)

const contentType = "text/markdown"

// Version describes one published documentation version.
type Version struct {
	Version     string `json:"version"`
	Status      string `json:"status"`
	ContentType string `json:"content_type"`
}

// Document is one rendered documentation page.
type Document struct {
	Version       string `json:"version"`
	Status        string `json:"status"`
	ContentType   string `json:"content_type"`
	Documentation string `json:"documentation"`
}

var versions = []Version{{Version: "v1", Status: "stable", ContentType: contentType}}

var versionPattern = regexp.MustCompile(`^v[0-9]{1,3}$`)

// Versions lists the published versions.
func Versions() []Version { return append([]Version(nil), versions...) }

// Get returns a document, or false when the version is not published.
func Get(version, lang string, vars Vars) (Document, bool) {
	if !versionPattern.MatchString(version) {
		return Document{}, false
	}
	for _, v := range versions {
		if v.Version != version {
			continue
		}
		language := normalise(lang)
		body, err := content.ReadFile("content/" + version + "." + language + ".md")
		if err != nil {
			return Document{}, false
		}
		text := render(string(body), vars)
		if profilePattern.MatchString(vars.Profile) {
			if extra, err := content.ReadFile("content/profiles/" + vars.Profile + "." + language + ".md"); err == nil {
				text = strings.TrimRight(text, "\n") + "\n\n" + render(string(extra), vars)
			}
		}
		return Document{
			Version:       v.Version,
			Status:        v.Status,
			ContentType:   v.ContentType,
			Documentation: text,
		}, true
	}
	return Document{}, false
}

// normalise accepts "pt", "pt-BR" and similar; everything else is English.
func normalise(lang string) string {
	if len(lang) >= 2 && (lang[:2] == "pt" || lang[:2] == "PT") {
		return "pt"
	}
	return "en"
}

// render removes the WebSocket section when there is no WebSocket URL and fills the
// placeholders. Values are substituted verbatim; they come from operator configuration.
func render(text string, v Vars) string {
	if v.WSURL == "" {
		text = wsBlock.ReplaceAllString(text, "")
	} else {
		text = strings.NewReplacer("<!--ws-->\n", "", "<!--/ws-->\n", "").Replace(text)
	}
	port := v.Port
	if port == "" {
		port = "8883"
	}
	host := v.Host
	if host == "" {
		host = "<broker-host>"
	}
	ca := v.CAFile
	if ca == "" {
		ca = "ca.crt"
	}
	return strings.NewReplacer(
		"{{host}}", host, "{{port}}", port, "{{ws_url}}", v.WSURL, "{{ca_file}}", ca,
	).Replace(text)
}
