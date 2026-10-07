// Package docs serves the MQTT service documentation embedded in the binary, in the
// shape the control plane's Documentation pages expect. Content is written once per
// language; an unknown or missing language falls back to English.
package docs

import (
	"embed"
	"regexp"
)

//go:embed content/*.md
var content embed.FS

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
func Get(version, lang string) (Document, bool) {
	if !versionPattern.MatchString(version) {
		return Document{}, false
	}
	for _, v := range versions {
		if v.Version != version {
			continue
		}
		body, err := content.ReadFile("content/" + version + "." + normalise(lang) + ".md")
		if err != nil {
			return Document{}, false
		}
		return Document{
			Version:       v.Version,
			Status:        v.Status,
			ContentType:   v.ContentType,
			Documentation: string(body),
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
