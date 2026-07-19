// Package routing is Meerkat's declarative routing model: predicates and
// filters are typed bricks — a type name plus schema-validated args — with
// the same shape everywhere (store, JSON export, admin API, console forms).
// The registry describes every brick (Catalog), so the console can generate
// its route editor from the schemas and new bricks never touch the engine.
package routing

import (
	"fmt"
	"sort"
	"strings"
)

// Spec is the serialized form of one predicate or filter on a route.
type Spec struct {
	Type string         `json:"type"`
	Args map[string]any `json:"args,omitempty"`
}

// ParamKind types a brick parameter.
type ParamKind string

// Parameter kinds understood by the schema decoder.
const (
	KindString     ParamKind = "string"
	KindStringList ParamKind = "stringList"
	KindInt        ParamKind = "int"
	KindBool       ParamKind = "bool"
)

// Param describes one argument of a brick — the contract the console uses to
// render its form field and the decoder uses to validate input.
type Param struct {
	Name     string    `json:"name"`
	Kind     ParamKind `json:"kind"`
	Required bool      `json:"required,omitempty"`
	Default  any       `json:"default,omitempty"`
	Doc      string    `json:"doc,omitempty"`
}

// decoded holds schema-validated, normalized args.
type decoded map[string]any

// decodeArgs validates raw args against the schema: unknown keys are
// rejected with the allowed list, required keys enforced, values coerced to
// their kind, defaults applied.
func decodeArgs(brick string, params []Param, in map[string]any) (decoded, error) {
	byName := make(map[string]Param, len(params))
	allowed := make([]string, 0, len(params))
	for _, p := range params {
		byName[p.Name] = p
		allowed = append(allowed, p.Name)
	}
	sort.Strings(allowed)

	out := decoded{}
	for key, raw := range in {
		p, ok := byName[key]
		if !ok {
			return nil, fmt.Errorf("%s: unknown arg %q (allowed: %s)", brick, key, strings.Join(allowed, ", "))
		}
		v, err := coerce(p.Kind, raw)
		if err != nil {
			return nil, fmt.Errorf("%s: arg %q: %w", brick, key, err)
		}
		out[key] = v
	}
	for _, p := range params {
		if _, ok := out[p.Name]; ok {
			continue
		}
		if p.Required {
			return nil, fmt.Errorf("%s: missing required arg %q", brick, p.Name)
		}
		if p.Default != nil {
			out[p.Name] = p.Default
		}
	}
	return out, nil
}

// coerce normalizes a JSON-decoded value to its declared kind.
func coerce(kind ParamKind, raw any) (any, error) {
	switch kind {
	case KindString:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("want string, got %T", raw)
		}
		return s, nil
	case KindStringList:
		switch v := raw.(type) {
		case string: // a single string is accepted as a one-element list
			return []string{v}, nil
		case []string:
			return v, nil
		case []any:
			out := make([]string, len(v))
			for i, e := range v {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("want list of strings, got %T at index %d", e, i)
				}
				out[i] = s
			}
			return out, nil
		default:
			return nil, fmt.Errorf("want list of strings, got %T", raw)
		}
	case KindInt:
		switch v := raw.(type) {
		case int:
			return v, nil
		case float64: // JSON numbers
			if v != float64(int(v)) {
				return nil, fmt.Errorf("want integer, got %v", v)
			}
			return int(v), nil
		default:
			return nil, fmt.Errorf("want integer, got %T", raw)
		}
	case KindBool:
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("want boolean, got %T", raw)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unknown param kind %q", kind)
	}
}

func (d decoded) str(name string) string {
	s, _ := d[name].(string)
	return s
}

func (d decoded) strs(name string) []string {
	s, _ := d[name].([]string)
	return s
}

func (d decoded) num(name string) int {
	n, _ := d[name].(int)
	return n
}

func (d decoded) boolean(name string) bool {
	b, _ := d[name].(bool)
	return b
}
