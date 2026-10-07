package api

import (
	"regexp"
	"strings"
)

// ACL types understood by Mosquitto's Dynamic Security plugin.
const (
	aclPublishSend     = "publishClientSend"
	aclPublishReceive  = "publishClientReceive"
	aclSubscribeLit    = "subscribeLiteral"
	aclSubscribePat    = "subscribePattern"
	aclUnsubscribeLit  = "unsubscribeLiteral"
	aclUnsubscribePat  = "unsubscribePattern"
	maxTopicBytes      = 1024
	maxPriority        = 1000
	maxACLsPerCreate   = 50
	maxDescriptionRune = 200
)

var aclTypes = map[string]bool{
	aclPublishSend: true, aclPublishReceive: true,
	aclSubscribeLit: true, aclSubscribePat: true,
	aclUnsubscribeLit: true, aclUnsubscribePat: true,
}

var roleNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ACLInput is an ACL as a caller describes it. Allow and Priority are optional: a missing
// allow means true and a missing priority means 0.
type ACLInput struct {
	Type     string `json:"type"`
	Topic    string `json:"topic"`
	Allow    *bool  `json:"allow"`
	Priority *int   `json:"priority"`
}

func (a ACLInput) allow() bool {
	return a.Allow == nil || *a.Allow
}

func (a ACLInput) priority() int {
	if a.Priority == nil {
		return 0
	}
	return *a.Priority
}

// validateACL returns an error code, or "" when the ACL is acceptable.
//
// The guardrails exist because a role is how access is granted: the broker's own control
// channel must never be reachable through a managed role, or any holder of that role could
// rewrite every user and role.
func validateACL(a ACLInput) string {
	if !aclTypes[a.Type] {
		return "invalid_acl"
	}
	if !validFilter(a.Topic) {
		return "invalid_acl"
	}
	if p := a.priority(); p < -maxPriority || p > maxPriority {
		return "invalid_acl"
	}
	// $CONTROL is the Dynamic Security channel. Wildcards at the first level do not match
	// topics that start with '$', so only an explicit $CONTROL ACL could grant it.
	if strings.HasPrefix(a.Topic, "$CONTROL") {
		return "forbidden_topic"
	}
	// Nothing may publish into the broker's reserved '$' namespace ($SYS is written by the
	// broker alone). Reading it, for monitoring, is fine.
	if a.Type == aclPublishSend && strings.HasPrefix(a.Topic, "$") {
		return "forbidden_topic"
	}
	return ""
}

// validFilter checks an MQTT topic filter: non-empty, bounded, printable, and with
// wildcards only where MQTT allows them ('+' as a whole level, '#' as the whole last
// level). Dynamic Security's %c and %u substitutions are ordinary characters here.
func validFilter(topic string) bool {
	if topic == "" || len(topic) > maxTopicBytes {
		return false
	}
	for _, r := range topic {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	levels := strings.Split(topic, "/")
	for i, level := range levels {
		switch {
		case strings.Contains(level, "#"):
			if level != "#" || i != len(levels)-1 {
				return false
			}
		case strings.Contains(level, "+"):
			if level != "+" {
				return false
			}
		}
	}
	return true
}

func validDescription(d string) bool {
	if len([]rune(d)) > maxDescriptionRune {
		return false
	}
	for _, r := range d {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
