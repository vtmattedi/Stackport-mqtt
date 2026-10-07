package tokenauth

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"
)

const cliUsage = `Usage:
  mqtt-admin token new --name <name> --scopes <scopes> [--expires <YYYY-MM-DD>]
      Generates a token, prints it once, and prints the entry to add to MQTT_ADMIN_TOKENS.
  mqtt-admin token hash
      Reads a token you already have from stdin and prints the entry hash.

Scopes are joined with '+': the presets read, write, admin, or scope names such as
mqtt.clients.delete (for example read+mqtt.clients.delete).
`

// RunCLI implements the `mqtt-admin token ...` commands and returns the exit code.
func RunCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, cliUsage)
		return 2
	}
	switch args[0] {
	case "new":
		return cliNew(args[1:], stdout, stderr)
	case "hash":
		return cliHash(stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprint(stderr, cliUsage)
		return 2
	}
}

func cliNew(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("token new", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "token name, used in logs and audit (a-z, 0-9, . _ -)")
	scopeSpec := fs.String("scopes", "", "scopes or presets joined with '+' (read, write, admin)")
	expires := fs.String("expires", "", "optional expiry, YYYY-MM-DD or RFC 3339")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	*scopeSpec = strings.ReplaceAll(*scopeSpec, ",", "+")
	if *name == "" || *scopeSpec == "" {
		_, _ = fmt.Fprint(stderr, cliUsage)
		return 2
	}

	token, err := Generate()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	entry := FormatEntry(*name, Hash(token), *scopeSpec, *expires)
	parsed, err := ParseEntries(entry)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	_, _ = fmt.Fprintf(stdout, "Token (shown once; store it in a password manager, it cannot be recovered):\n%s\n\n", token)
	_, _ = fmt.Fprintf(stdout, "Add this entry to MQTT_ADMIN_TOKENS (separate several entries with ';'):\n%s\n\n", entry)
	_, _ = fmt.Fprintf(stdout, "Grants: %s\n", strings.Join(parsed[0].Scopes, ", "))
	if parsed[0].ExpiresAt.IsZero() {
		_, _ = fmt.Fprintln(stdout, "Expires: never (consider --expires for tokens that can change anything)")
	} else {
		_, _ = fmt.Fprintf(stdout, "Expires: %s\n", parsed[0].ExpiresAt.Format("2006-01-02 15:04 UTC"))
	}
	return 0
}

func cliHash(stdin io.Reader, stdout, stderr io.Writer) int {
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		_, _ = fmt.Fprintln(stderr, "error: no token on stdin")
		return 2
	}
	token := strings.TrimSpace(line)
	if len(token) < MinTokenLength {
		_, _ = fmt.Fprintf(stderr, "error: refusing a token shorter than %d characters; use `token new` instead\n", MinTokenLength)
		return 2
	}
	_, _ = fmt.Fprintln(stdout, Hash(token))
	return 0
}

// FormatEntry builds an MQTT_ADMIN_TOKENS entry.
func FormatEntry(name, hash, scopeSpec, expires string) string {
	entry := name + ":" + hash + ":" + scopeSpec
	if expires != "" {
		entry += ":" + expires
	}
	return entry
}
