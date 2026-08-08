package features

import (
	"slices"
	"strings"
	"testing"
)

func TestEnableHas(t *testing.T) {
	t.Cleanup(Reset)
	if Has(Directories) {
		t.Fatal("feature enabled before Enable")
	}
	Enable(Directories, Cluster)
	if !Has(Directories) || !Has(Cluster) {
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

// Require is what a handler calls before WRITING something an Enterprise
// feature owns. Its error names the feature, because "403" tells an
// administrator nothing about what to buy or what to turn on.
func TestRequireNamesTheFeature(t *testing.T) {
	t.Cleanup(Reset)
	err := Require(MultiTenant)
	if err == nil {
		t.Fatal("Require must refuse a feature that is not enabled")
	}
	if !strings.Contains(err.Error(), MultiTenant) {
		t.Fatalf("error = %q, want it to name %q", err, MultiTenant)
	}
	Enable(MultiTenant)
	if err := Require(MultiTenant); err != nil {
		t.Fatalf("Require after Enable = %v, want nil", err)
	}
}

// All is what a license payload and the console's roster are written against:
// a key that exists but is missing from it would be unsellable and invisible.
func TestAllListsEveryKey(t *testing.T) {
	for _, name := range []string{
		MultiTenant, Directories, SAML, SCIM, BusinessHours, Cluster, AuditExport, WhiteLabel,
	} {
		if !slices.Contains(All, name) {
			t.Errorf("All is missing %q", name)
		}
	}
	if len(All) != 8 {
		t.Fatalf("All has %d entries, want 8", len(All))
	}
}
