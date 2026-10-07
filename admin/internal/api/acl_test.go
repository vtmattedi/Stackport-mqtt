package api

import (
	"strings"
	"testing"
)

func acl(typ, topic string) ACLInput { return ACLInput{Type: typ, Topic: topic} }

func TestValidateACLAcceptsOrdinaryRules(t *testing.T) {
	ok := []ACLInput{
		acl(aclPublishSend, "#"),
		acl(aclPublishReceive, "devices/+/events/#"),
		acl(aclSubscribePat, "devices/%u/#"),
		acl(aclSubscribeLit, "status"),
		acl(aclUnsubscribePat, "devices/%c/#"),
		acl(aclUnsubscribeLit, "a/b"),
		acl(aclSubscribePat, "$SYS/#"),      // monitoring clients may read statistics
		acl(aclPublishReceive, "$SYS/#"),    // ...and receive them
		acl(aclPublishSend, "Control/time"), // capital letters, plain topic
		{Type: aclPublishSend, Topic: "a", Priority: intp(-1000)},
		{Type: aclPublishSend, Topic: "a", Priority: intp(1000)},
		{Type: aclPublishSend, Topic: "a", Allow: boolp(false)},
	}
	for _, a := range ok {
		if code := validateACL(a); code != "" {
			t.Errorf("%+v rejected: %s", a, code)
		}
	}
}

func TestValidateACLRefusesTheControlChannel(t *testing.T) {
	for _, typ := range []string{aclPublishSend, aclPublishReceive, aclSubscribeLit, aclSubscribePat, aclUnsubscribeLit, aclUnsubscribePat} {
		for _, topic := range []string{
			"$CONTROL", "$CONTROL/#", "$CONTROL/dynamic-security/v1",
			"$CONTROL/dynamic-security/#", "$CONTROL/dynamic-security/v1/response",
		} {
			if got := validateACL(acl(typ, topic)); got != "forbidden_topic" {
				t.Errorf("%s on %s: got %q, want forbidden_topic", typ, topic, got)
			}
		}
	}
}

func TestValidateACLNobodyMayPublishIntoTheReservedNamespace(t *testing.T) {
	for _, topic := range []string{"$SYS/broker/uptime", "$SYS/#", "$anything", "$share/g/t"} {
		if got := validateACL(acl(aclPublishSend, topic)); got != "forbidden_topic" {
			t.Errorf("publish on %s: got %q", topic, got)
		}
	}
}

func TestValidateACLRejectsMalformedRules(t *testing.T) {
	bad := []ACLInput{
		acl("", "a"),
		acl("publish", "a"),
		acl("PublishClientSend", "a"), // types are case-sensitive
		acl(aclPublishSend, ""),
		acl(aclPublishSend, "a/#/b"),  // '#' must be last
		acl(aclPublishSend, "a#"),     // '#' must be a whole level
		acl(aclPublishSend, "a/b#"),   // ditto
		acl(aclPublishSend, "a+/b"),   // '+' must be a whole level
		acl(aclPublishSend, "a/+b"),   // ditto
		acl(aclPublishSend, "a\x00b"), // control character
		acl(aclPublishSend, "a\nb"),   // control character
		acl(aclPublishSend, strings.Repeat("a", maxTopicBytes+1)),
		{Type: aclPublishSend, Topic: "a", Priority: intp(1001)},
		{Type: aclPublishSend, Topic: "a", Priority: intp(-1001)},
	}
	for _, a := range bad {
		if code := validateACL(a); code != "invalid_acl" {
			t.Errorf("%q / %q: got %q, want invalid_acl", a.Type, a.Topic, code)
		}
	}
}

func TestValidateACLChecksTheControlChannelEvenWhenOtherwiseMalformed(t *testing.T) {
	// A malformed control-channel rule is simply invalid; it must never be accepted.
	if got := validateACL(acl(aclPublishSend, "$CONTROL/#/x")); got == "" {
		t.Fatal("accepted")
	}
}

func TestACLDefaults(t *testing.T) {
	a := ACLInput{Type: aclPublishSend, Topic: "a"}
	if !a.allow() || a.priority() != 0 {
		t.Fatal("a missing allow means true and a missing priority means 0")
	}
	if (ACLInput{Allow: boolp(false)}).allow() {
		t.Fatal("an explicit false must stay false")
	}
}

func TestRoleNames(t *testing.T) {
	for _, ok := range []string{"nmnw", "a", "app-1", "Team.A_b", strings.Repeat("a", 64)} {
		if !roleNameRE.MatchString(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-a", ".a", "a b", "a/b", "a#", "../x", strings.Repeat("a", 65), "ação"} {
		if roleNameRE.MatchString(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestDescriptionLimits(t *testing.T) {
	if !validDescription("") || !validDescription("Gateways and devices") || !validDescription(strings.Repeat("é", 200)) {
		t.Fatal("ordinary descriptions are valid")
	}
	if validDescription(strings.Repeat("a", 201)) || validDescription("line\nbreak") || validDescription("nul\x00") {
		t.Fatal("overlong or control-character descriptions are invalid")
	}
}

func intp(v int) *int    { return &v }
func boolp(v bool) *bool { return &v }
