package llrules_test

import (
	"context"
	"net"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/llrules"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
)

func TestDNSOverTCP(t *testing.T) {
	lltest.RunInSubprocess(t, func() {
		err := landlock.V5.BestEffort().Restrict(llrules.DNS())
		if err != nil {
			t.Fatalf("Enabling Landlock: %v", err)
		}

		r := net.Resolver{
			PreferGo: true,
		}
		_, err = r.LookupHost(context.Background(), "localhost")
		if err != nil {
			t.Errorf("Unexpected DNS error: %v", err)
		}
	})
}

func TestDNSOverTCP_fail(t *testing.T) {
	lltest.RequireABI(t, 1)

	lltest.RunInSubprocess(t, func() {
		err := landlock.V5.BestEffort().Restrict()
		if err != nil {
			t.Fatalf("Enabling Landlock: %v", err)
		}

		r := net.Resolver{
			PreferGo: true,
		}
		_, err = r.LookupHost(context.Background(), "localhost")
		if err == nil {
			t.Errorf("Expected DNS error, but got success")
		}
	})
}
