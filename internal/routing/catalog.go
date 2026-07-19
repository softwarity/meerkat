package routing

import "sort"

// CatalogEntry is the self-description of one brick — what the admin API
// serves so the console can generate the route editor forms, and what the
// documentation is derived from. One source of truth for four layers.
type CatalogEntry struct {
	Kind   string  `json:"kind"`            // "predicate" | "filter"
	Type   string  `json:"type"`            // e.g. "path", "inject-head"
	Phase  string  `json:"phase,omitempty"` // filters: request | response | terminal
	Doc    string  `json:"doc"`
	Params []Param `json:"params"`
}

// Catalog returns every registered predicate and filter, sorted by kind then
// type.
func Catalog() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(predicateRegistry)+len(filterRegistry))
	for _, d := range predicateRegistry {
		out = append(out, CatalogEntry{Kind: "predicate", Type: d.Type, Doc: d.Doc, Params: d.Params})
	}
	for _, d := range filterRegistry {
		out = append(out, CatalogEntry{Kind: "filter", Type: d.Type, Phase: string(d.Phase), Doc: d.Doc, Params: d.Params})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func joinSorted(names []string) string {
	sort.Strings(names)
	s := ""
	for i, n := range names {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}
