package audit

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestInjectNamespaceFilterEmpty(t *testing.T) {
	query := url.Values{}
	result := InjectNamespaceFilter(query, "testns")

	var filters map[string][]string
	if err := json.Unmarshal([]byte(result.Get("filters")), &filters); err != nil {
		t.Fatalf("failed to parse filters: %v", err)
	}

	labels := filters["label"]
	if len(labels) != 1 {
		t.Fatalf("label filters len = %d, want 1", len(labels))
	}
	if labels[0] != "ltkk.run/namespace=testns" {
		t.Errorf("label filter = %q", labels[0])
	}
}

func TestInjectNamespaceFilterMerge(t *testing.T) {
	existing := map[string][]string{
		"status": {"running"},
		"label":  {"env=prod"},
	}
	encoded, _ := json.Marshal(existing)

	query := url.Values{}
	query.Set("filters", string(encoded))
	query.Set("all", "true")

	result := InjectNamespaceFilter(query, "myns")

	// Preserve other query params
	if result.Get("all") != "true" {
		t.Error("all param lost")
	}

	var filters map[string][]string
	if err := json.Unmarshal([]byte(result.Get("filters")), &filters); err != nil {
		t.Fatalf("failed to parse filters: %v", err)
	}

	// Status filter preserved
	if len(filters["status"]) != 1 || filters["status"][0] != "running" {
		t.Errorf("status filter = %v", filters["status"])
	}

	// Label filters should have both existing and namespace
	labels := filters["label"]
	if len(labels) != 2 {
		t.Fatalf("label filters len = %d, want 2", len(labels))
	}

	found := false
	for _, l := range labels {
		if l == "ltkk.run/namespace=myns" {
			found = true
		}
	}
	if !found {
		t.Error("namespace label filter not found")
	}
}

func TestInjectNamespaceFilterInvalidExisting(t *testing.T) {
	query := url.Values{}
	query.Set("filters", "not-valid-json")

	result := InjectNamespaceFilter(query, "testns")

	var filters map[string][]string
	if err := json.Unmarshal([]byte(result.Get("filters")), &filters); err != nil {
		t.Fatalf("failed to parse filters: %v", err)
	}

	if len(filters["label"]) != 1 {
		t.Fatalf("label filters len = %d", len(filters["label"]))
	}
}
