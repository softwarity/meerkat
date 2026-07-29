package admin

import (
	"net/http"

	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// Route probing (ROUTE-12), infra plane. Two ways in, one answer:
//
//   - give a targetRouteId and the probe SYNTHESIZES a request from that
//     route's predicates ("build me something that should land here");
//   - give a request and it tells you where that request actually lands
//     ("why does this call reach the wrong service?").
//
// Sending both is the useful loop: the console pre-fills by synthesis, the
// admin adjusts a header, and re-runs.
//
// It matches, it never proxies: no upstream is contacted, nothing is written.
func (a *API) registerProbe(mux *http.ServeMux) {
	mux.Handle("POST /api/routes/probe", a.infraAdmin(a.probeRoutes))
}

type probePayload struct {
	// TargetRouteID seeds the synthesis and names the route the caller expects
	// to win. Optional.
	TargetRouteID string `json:"targetRouteId,omitempty"`
	// Request overrides the synthesis, field by field. Optional.
	Request *routing.Synthesis `json:"request,omitempty"`
}

func (a *API) probeRoutes(w http.ResponseWriter, r *http.Request, _ store.User) {
	var p probePayload
	if err := decodeStrict(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed probe: "+err.Error())
		return
	}
	if p.TargetRouteID == "" && p.Request == nil {
		writeErr(w, http.StatusUnprocessableEntity,
			"nothing to probe: pass targetRouteId, a request, or both")
		return
	}

	var synth routing.Synthesis
	if p.TargetRouteID != "" {
		route, err := a.st.GetRoute(r.Context(), p.TargetRouteID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "unknown route "+p.TargetRouteID)
			return
		}
		// Probe the route the ENGINE runs, references resolved: a predicate on
		// "${tenant-host}" must be tried with the host, not with the reference.
		values, err := a.st.VaultValues(r.Context(), vault.ScopeInfra)
		if err != nil {
			a.internal(w, err)
			return
		}
		expanded, _, err := gateway.ExpandRoute(route, values)
		if err != nil {
			a.internal(w, err)
			return
		}
		synth = routing.Synthesize(expanded.Predicates)
		if !route.Enabled {
			synth.Notes = append(synth.Notes, routing.Note{
				Type:   "route",
				Reason: "this route is disabled, so it is not in the live snapshot and cannot win",
			})
		}
	}
	if p.Request != nil {
		synth = mergeSynthesis(synth, *p.Request)
	}
	writeJSON(w, http.StatusOK, a.router.Probe(p.TargetRouteID, synth))
}

// mergeSynthesis lets the caller override what the synthesis proposed, field
// by field: an admin edits one header and keeps the rest.
func mergeSynthesis(base, over routing.Synthesis) routing.Synthesis {
	out := base
	if over.Method != "" {
		out.Method = over.Method
	}
	if over.Path != "" {
		out.Path = over.Path
	}
	if over.Host != "" {
		out.Host = over.Host
	}
	if over.RemoteAddr != "" {
		out.RemoteAddr = over.RemoteAddr
	}
	if !over.At.IsZero() {
		out.At = over.At
	}
	if over.Lottery != 0 {
		out.Lottery = over.Lottery
	}
	// A map sent by the caller REPLACES the synthesized one: an admin removing
	// a header must be able to remove it, not merely to add another.
	if over.Headers != nil {
		out.Headers = over.Headers
	}
	if over.Cookies != nil {
		out.Cookies = over.Cookies
	}
	if over.Query != nil {
		out.Query = over.Query
	}
	return out
}
