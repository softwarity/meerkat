package features

import (
	"slices"
	"testing"
)

func TestEnableHas(t *testing.T) {
	t.Cleanup(Reset)
	if Has(SSOOIDC) {
		t.Fatal("feature enabled before Enable")
	}
	Enable(SSOOIDC, Cluster)
	if !Has(SSOOIDC) || !Has(Cluster) {
		t.Fatal("enabled features not reported")
	}
	if Has(SAML) {
		t.Fatal("unrequested feature reported enabled")
	}
}

func TestEnabledSnapshot(t *testing.T) {
	t.Cleanup(Reset)
	Enable(Cluster, AuditExport)
	got := Enabled()
	want := []string{AuditExport, Cluster}
	if !slices.Equal(got, want) {
		t.Fatalf("Enabled() = %v, want %v", got, want)
	}
}
