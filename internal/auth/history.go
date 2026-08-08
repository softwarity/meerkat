package auth

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// Sign-in history: every COMPLETED login (password, password+code, passkey)
// is recorded and listed on /profile/history. A durable random cookie names
// the browser - its hash rides on each event so the list can badge the rows
// made from THIS browser, same spirit as the passkey/trusted-browser badges.

// browserCookieName carries the durable browser identifier - an opaque random
// token with no authority whatsoever; only its hash is stored, per event.
const browserCookieName = "MEERKAT_BROWSER"

// How a sign-in completed; stored per event, translated at display time.
const (
	loginMethodPassword = "password"
	loginMethodTOTP     = "totp" // password + code (challenge or forced enrolment)
	loginMethodPasskey  = "passkey"
)

func browserTokenOf(r *http.Request) string {
	if c, err := r.Cookie(browserCookieName); err == nil {
		return c.Value
	}
	return ""
}

// clientIP is the peer as seen from the gateway: the rightmost X-Forwarded-For
// entry when a fronting proxy added one (the only hop-controlled value),
// otherwise the connection's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return hostOnly(r.RemoteAddr)
}

// countryOf captures the viewer country a fronting CDN/LB resolved, when one
// did: the gateway is offline-first and never calls a GeoIP service itself.
// Cloudflare's "XX" (unknown) and "T1" (Tor) are treated as no answer.
func countryOf(r *http.Request) string {
	for _, name := range []string{"CF-IPCountry", "CloudFront-Viewer-Country", "X-Geo-Country"} {
		v := strings.ToUpper(strings.TrimSpace(r.Header.Get(name)))
		if len(v) == 2 && v != "XX" && v != "T1" {
			return v
		}
	}
	return ""
}

// recordLogin appends a sign-in event, minting the browser cookie on first
// sight. Best-effort: history must never fail a login. Call it BEFORE the
// redirect is written so the cookie can still ride the response.
func (h *Handler) recordLogin(w http.ResponseWriter, r *http.Request, userID, method string) {
	token := browserTokenOf(r)
	if token == "" {
		t, err := randToken()
		if err != nil {
			slog.Warn("browser token mint failed", "err", err)
		} else {
			token = t
			http.SetCookie(w, &http.Cookie{
				Name: browserCookieName, Value: token, Path: "/",
				HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
				MaxAge: 2 * 365 * 24 * 3600,
			})
		}
	}
	e := store.LoginEvent{
		ID:      randomID(),
		Method:  method,
		Label:   browserLabel(r),
		IP:      clientIP(r),
		Country: countryOf(r),
		At:      time.Now().Unix(),
	}
	if token != "" {
		e.BrowserHash = hashTrust(token)
	}
	if err := h.st.AddLoginEvent(r.Context(), e, userID); err != nil {
		slog.Warn("sign-in history record failed", "user", userID, "err", err)
	}
}

// ---- the /profile/history page ----

var profileHistoryPage = flowPage("profile-history", profileHistoryBody)

type profileHistoryData struct {
	flowChrome
	Events []loginEventView
}

// loginEventView is one history row, pre-formatted: the browser label, the
// localized method chip, the IP - country line, the localized timestamp.
type loginEventView struct {
	Label   string
	Method  string
	Meta    string // "IP - country", possibly empty
	When    string
	Current bool
}

const profileHistoryBody = `    <style>
      /* the list lives in a PANEL, same family as the option blocks; the
         section title sits INSIDE it (the trusted-browsers convention). */
      .lh-panel {
        width: 100%; padding: 2px 16px 6px; position: relative;
        background: var(--mk-surface-container-high);
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
      }
      /* same hairline mint accent as the flow card's top edge */
      .lh-panel::before {
        content: ''; position: absolute; inset: 0 0 auto 0; height: 2px;
        border-radius: var(--mk-radius-small) var(--mk-radius-small) 0 0;
        background: linear-gradient(90deg, transparent, var(--mk-primary), transparent);
        opacity: calc(.85 * var(--mk-glow, 1));
      }
      .lh-panel h2 {
        margin: 0; padding: 12px 0 4px; text-align: left;
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .16em;
        text-transform: uppercase; color: var(--mk-on-surface-variant); font-weight: 600;
      }
      /* when the list grows past a few, scroll INSIDE the panel */
      .lh-rows { max-height: 52vh; overflow-y: auto; }
      .lh-row { display: flex; align-items: center; gap: 12px; padding: 11px 0; }
      .lh-row + .lh-row { border-top: 1px solid color-mix(in srgb, var(--mk-outline) 45%, transparent); }
      .lh-lines { flex: 1; min-width: 0; display: grid; gap: 3px; text-align: left; }
      .lh-label { font-size: .88rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      /* the current browser needs no browser/os/ip - we ARE on it */
      .lh-label.here { color: var(--mk-primary); font-weight: 500; }
      .lh-meta {
        font-family: var(--mk-mono); font-size: .66rem;
        color: var(--mk-on-surface-variant); overflow-wrap: anywhere;
      }
      .lh-method {
        font-family: var(--mk-mono); font-size: .58rem; letter-spacing: .1em;
        text-transform: uppercase; color: var(--mk-on-surface-variant);
        padding: 3px 9px; border-radius: 999px; white-space: nowrap;
        border: 1px solid var(--mk-outline);
      }
      .lh-when {
        font-family: var(--mk-mono); font-size: .68rem;
        color: var(--mk-on-surface-variant); white-space: nowrap;
      }
      .hint-line { margin: 0; padding: 8px 0 12px; font-size: .74rem; color: var(--mk-on-surface-variant); }
    </style>
    <div class="lh-panel">
      <h2>{{.T.signinHistory}}</h2>
      <div class="lh-rows">
      {{range .Events}}
      <div class="lh-row">
        <div class="lh-lines">
          <span class="lh-label{{if .Current}} here{{end}}">{{.Label}}</span>
          {{if .Meta}}<span class="lh-meta">{{.Meta}}</span>{{end}}
        </div>
        <span class="lh-method">{{.Method}}</span>
        <span class="lh-when">{{.When}}</span>
      </div>
      {{else}}
      <p class="hint-line">{{.T.historyEmpty}}</p>
      {{end}}
      </div>
    </div>
    <p class="back"><a href="/profile/security">{{.T.back}}</a></p>
`

// showProfileHistory renders the sign-in history, reached from Security.
func (h *Handler) showProfileHistory(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return
	}
	data := profileHistoryData{flowChrome: h.flowData(r, "titleHistory")}
	// Timestamps land in the user's own timezone when it resolves.
	loc := time.Local
	if u, err := h.st.GetUserByID(r.Context(), sess.UserID); err == nil && u.Timezone != "" {
		if l, err := time.LoadLocation(u.Timezone); err == nil {
			loc = l
		}
	}
	currentHash := ""
	if token := browserTokenOf(r); token != "" {
		currentHash = hashTrust(token)
	}
	events, err := h.st.ListLoginEvents(r.Context(), sess.UserID)
	if err != nil {
		slog.Warn("sign-in history list failed", "user", sess.UserID, "err", err)
	}
	for _, e := range events {
		current := e.BrowserHash != "" && e.BrowserHash == currentHash
		v := loginEventView{
			Method:  h.tr(r, methodKey(e.Method)),
			When:    time.Unix(e.At, 0).In(loc).Format("2006-01-02 15:04"),
			Current: current,
		}
		if current {
			// We ARE this browser: no need to name the browser/OS/IP.
			v.Label = h.tr(r, "thisBrowser")
		} else {
			v.Label = e.Label
			var meta []string
			if e.IP != "" {
				meta = append(meta, e.IP)
			}
			if e.Country != "" {
				meta = append(meta, e.Country)
			}
			v.Meta = strings.Join(meta, " - ")
		}
		data.Events = append(data.Events, v)
	}
	writeFlow(w, profileHistoryPage, data, http.StatusOK)
}

func methodKey(method string) string {
	switch method {
	case loginMethodTOTP:
		return "methodTotp"
	case loginMethodPasskey:
		return "methodPasskey"
	default:
		return "methodPassword"
	}
}
