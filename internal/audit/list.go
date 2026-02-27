package audit

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// InjectNamespaceFilter adds a label filter for ltkk.run/namespace to the
// query parameters of a container list request. It merges with any existing
// filters in the "filters" query parameter.
// Returns the modified query and a warning string (empty if no issues).
func InjectNamespaceFilter(query url.Values, namespace string) (url.Values, string) {
	result := make(url.Values)
	for k, v := range query {
		result[k] = v
	}

	var filters map[string][]string
	var warning string

	if existing := result.Get("filters"); existing != "" {
		if err := json.Unmarshal([]byte(existing), &filters); err != nil {
			warning = fmt.Sprintf("malformed filters query parameter (dropped): %v", err)
			filters = make(map[string][]string)
		}
	} else {
		filters = make(map[string][]string)
	}

	// Add namespace label filter
	labelFilter := LabelNamespace + "=" + namespace
	filters["label"] = append(filters["label"], labelFilter)

	encoded, _ := json.Marshal(filters)
	result.Set("filters", string(encoded))

	return result, warning
}
