package auth

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/store"
)

// Personal API tokens (AUTH-16): self-service on /profile/tokens. A token
// CAPTURES the caller's current context (active tenant + active group), so an
// API call needs no interactive tenant/group choice. The clear value is shown
// ONCE at creation; only its hash lives in the store. Tokens can be disabled
// (toggled off) or revoked (deleted).

var apiTokensPage = flowPage("profile-tokens", apiTokensBody)

// apiTokenDurations are the offered validities, in days (0 = never).
var apiTokenDurations = []struct {
	Days  int
	Label string // localized at render via T
}{
	{30, "days30"}, {60, "days60"}, {90, "days90"}, {365, "year1"}, {0, "never"},
}

type apiTokenView struct {
	ID       string
	Name     string
	Prefix   string
	Context  string // "acme" or "acme - Support"
	Enabled  bool
	Expiry   string // "" = never, else localized date, or "expired"
	LastUsed string // "" = never used
	Expired  bool
}

type apiTokensData struct {
	flowChrome
	Error     string
	Tokens    []apiTokenView
	Created   string // the clear token, shown once right after creation
	Context   string // the CURRENT session context a new token would capture
	NoTenant  bool   // no active tenant: a token would carry no roles
	Durations []durationOption
}

type durationOption struct {
	Days  int
	Label string
}

const apiTokensBody = `    <style>
      .tk-ctx { margin: 0 0 10px; font-size: .82rem; color: var(--mk-on-surface-variant); text-align: left; }
      .tk-add { width: 100%; margin: 0 0 6px; }
      /* the list lives in a PANEL, title INSIDE (the trusted-browsers convention) */
      .tk-panel {
        width: 100%; padding: 2px 16px 6px; margin-top: 6px; position: relative;
        background: var(--mk-surface-container-high);
        border: 1px solid var(--mk-outline); border-radius: var(--mk-radius-small);
      }
      /* same hairline mint accent as the flow card's top edge */
      .tk-panel::before {
        content: ''; position: absolute; inset: 0 0 auto 0; height: 2px;
        border-radius: var(--mk-radius-small) var(--mk-radius-small) 0 0;
        background: linear-gradient(90deg, transparent, var(--mk-primary), transparent);
        opacity: calc(.85 * var(--mk-glow, 1));
      }
      .tk-panel h2 {
        margin: 0; padding: 12px 0 4px; text-align: left;
        font-family: var(--mk-mono); font-size: .62rem; letter-spacing: .16em;
        text-transform: uppercase; color: var(--mk-on-surface-variant); font-weight: 600;
      }
      .tk-rows { max-height: 46vh; overflow-y: auto; }
      .tk { display: flex; align-items: center; gap: 10px; padding: 10px 0; }
      .tk + .tk { border-top: 1px solid color-mix(in srgb, var(--mk-outline) 45%, transparent); }
      .tk-lines { flex: 1; min-width: 0; display: grid; gap: 2px; text-align: left; }
      .tk-name { font-size: .88rem; display: flex; align-items: center; gap: 8px; }
      .tk-meta { font-family: var(--mk-mono); font-size: .64rem; color: var(--mk-on-surface-variant); overflow-wrap: anywhere; }
      .tk-off { font-family: var(--mk-mono); font-size: .58rem; letter-spacing: .1em; text-transform: uppercase;
        color: var(--mk-on-surface-variant); border: 1px solid var(--mk-outline); border-radius: 999px; padding: 1px 7px; }
      .tk-exp { color: var(--mk-error); }
      .tk form { margin: 0; padding: 0; width: auto; display: inline-grid;
        background: none; border: 0; box-shadow: none; backdrop-filter: none; animation: none; }
      .tk form::before { display: none; }
      .tk-btn {
        margin: 0; padding: 0; width: 28px; height: 28px; border: 1px solid transparent; border-radius: 50%;
        background: none; box-shadow: none; color: var(--mk-on-surface-variant);
        cursor: pointer; display: grid; place-items: center;
      }
      .tk-btn svg { display: block; }
      .tk-btn:hover { border-color: var(--mk-outline); background: var(--mk-surface-container); filter: none; box-shadow: none; }
      .tk-btn.x:hover { color: var(--mk-error); }
      .tk-btn:active { transform: none; }
      .hint-line { margin: 0 0 8px; font-size: .74rem; color: var(--mk-on-surface-variant); text-align: left; }
      /* modal (native dialog), styled like the flow card */
      .tk-dlg {
        width: min(340px, 92vw); padding: 20px; border: 1px solid var(--mk-outline);
        border-radius: var(--mk-radius, 12px); background: var(--mk-surface-container);
        color: var(--mk-on-surface); box-shadow: 0 20px 60px rgba(0,0,0,.4);
      }
      .tk-dlg::backdrop { background: rgba(0,0,0,.5); backdrop-filter: blur(2px); }
      .tk-dlg h3 { margin: 0 0 14px; font-size: 1rem; font-weight: 600; text-align: left; }
      .tk-dlg form { margin: 0; padding: 0; width: 100%; background: none; border: 0;
        box-shadow: none; backdrop-filter: none; animation: none; display: grid; gap: 10px; }
      .tk-dlg form::before { display: none; }
      .tk-dlg label { display: grid; gap: 4px; text-align: left; font-size: .78rem; color: var(--mk-on-surface-variant); }
      .tk-dlg select, .tk-dlg input {
        width: 100%; padding: 9px 10px; border-radius: var(--mk-radius-small);
        background: var(--mk-surface); color: var(--mk-on-surface); border: 1px solid var(--mk-outline);
        font-size: .9rem;
      }
      .tk-dlg-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 6px; }
      .tk-dlg-actions button { margin: 0; padding: 8px 16px; width: auto; }
      .tk-ghost {
        background: none; border: 1px solid var(--mk-outline); color: var(--mk-on-surface);
        box-shadow: none;
      }
      .tk-ghost:hover { border-color: var(--mk-primary); filter: none; box-shadow: none; }
      /* the copy button sits INSIDE the token box, top-right */
      .tk-copy { position: relative; margin: 4px 0 12px; }
      .tk-copy code {
        display: block; font-family: var(--mk-mono); font-size: .8rem; word-break: break-all;
        padding: 8px 42px 8px 10px; border-radius: var(--mk-radius-small);
        background: var(--mk-surface); border: 1px solid var(--mk-outline);
      }
      .tk-copy-btn {
        position: absolute; top: 5px; right: 5px; margin: 0; width: 28px; height: 28px; padding: 0;
        border: 1px solid transparent; border-radius: var(--mk-radius-small);
        background: var(--mk-surface-container-high);
        color: var(--mk-on-surface-variant); cursor: pointer; display: grid; place-items: center; box-shadow: none;
      }
      .tk-copy-btn:hover { color: var(--mk-primary); border-color: var(--mk-outline); filter: none; box-shadow: none; }
      .tk-copy-btn:active { transform: none; }
      .tk-copy-btn.ok { color: var(--mk-primary); border-color: var(--mk-primary); }
      .tk-warn { margin: 0 0 4px; font-size: .76rem; color: var(--mk-on-surface-variant); text-align: left; }
    </style>
    <p class="lead">{{.T.apiTokens}}</p>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}

    <p class="tk-ctx">{{.T.tokenContext}} <strong>{{.Context}}</strong></p>
    {{if .NoTenant}}<p class="hint-line">{{.T.tokenNoTenant}}</p>{{end}}
    <button type="button" class="choice tk-add" id="tk-open">{{.T.tokenCreate}}</button>

    <dialog id="tk-create-dlg" class="tk-dlg">
      <h3>{{.T.tokenCreate}}</h3>
      <form method="post" action="/profile/tokens">
        <label>{{.T.tokenNameLabel}}
          <input name="name" placeholder="{{.T.tokenNamePlaceholder}}" autocomplete="off" maxlength="60" required autofocus>
        </label>
        <label>{{.T.tokenValidity}}
          <select name="days">
            {{range .Durations}}<option value="{{.Days}}"{{if eq .Days 90}} selected{{end}}>{{.Label}}</option>{{end}}
          </select>
        </label>
        <div class="tk-dlg-actions">
          <button type="button" class="tk-ghost" id="tk-cancel">{{.T.cancel}}</button>
          <button type="submit" name="action" value="create">{{.T.tokenCreate}}</button>
        </div>
      </form>
    </dialog>

    {{if .Created}}
    <dialog id="tk-reveal-dlg" class="tk-dlg">
      <h3>{{.T.tokenCreatedLead}}</h3>
      <div class="tk-copy">
        <code id="tk-value">{{.Created}}</code>
        <button type="button" class="tk-copy-btn" id="tk-copy" title="{{.T.copy}}" aria-label="{{.T.copy}}">
          <svg viewBox="0 -960 960 960" fill="currentColor" aria-hidden="true" width="16" height="16"><path d="M360-240q-33 0-56.5-23.5T280-320v-480q0-33 23.5-56.5T360-880h360q33 0 56.5 23.5T800-800v480q0 33-23.5 56.5T720-240H360Zm0-80h360v-480H360v480ZM200-80q-33 0-56.5-23.5T120-160v-520q0-17 11.5-28.5T160-720q17 0 28.5 11.5T200-680v520h400q17 0 28.5 11.5T640-120q0 17-11.5 28.5T600-80H200Zm160-240v-480 480Z"/></svg>
        </button>
      </div>
      <p class="tk-warn">{{.T.tokenCreatedWarn}}</p>
      <div class="tk-dlg-actions">
        <button type="button" id="tk-done">{{.T.done}}</button>
      </div>
    </dialog>
    {{end}}

    {{if .Tokens}}
    <div class="tk-panel">
      <h2>{{.T.tokenListTitle}}</h2>
      <div class="tk-rows">
      {{range .Tokens}}
      <div class="tk">
        <div class="tk-lines">
          <span class="tk-name">{{.Name}}{{if not .Enabled}}<span class="tk-off">{{$.T.tokenDisabled}}</span>{{end}}</span>
          <span class="tk-meta">{{.Prefix}}... - {{.Context}}{{if .Expiry}} - <span{{if .Expired}} class="tk-exp"{{end}}>{{.Expiry}}</span>{{end}}{{if .LastUsed}} - {{.LastUsed}}{{end}}</span>
        </div>
        <form method="post" action="/profile/tokens">
          <input type="hidden" name="id" value="{{.ID}}">
          <button class="tk-btn" type="submit" name="action" value="toggle" title="{{if .Enabled}}{{$.T.tokenDisable}}{{else}}{{$.T.tokenEnable}}{{end}}" aria-label="{{if .Enabled}}{{$.T.tokenDisable}}{{else}}{{$.T.tokenEnable}}{{end}}">
            {{if .Enabled}}<svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" aria-hidden="true"><circle cx="12" cy="12" r="7"/></svg>{{else}}<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" aria-hidden="true"><circle cx="12" cy="12" r="6.5"/></svg>{{end}}
          </button>
        </form>
        <button class="tk-btn x" type="button" data-revoke="{{.ID}}" data-name="{{.Name}}" title="{{$.T.tokenRevoke}}" aria-label="{{$.T.tokenRevoke}}">
          <svg viewBox="0 -960 960 960" width="15" height="15" fill="currentColor" aria-hidden="true"><path d="m256-200-56-56 224-224-224-224 56-56 224 224 224-224 56 56-224 224 224 224-56 56-224-224-224 224Z"/></svg>
        </button>
      </div>
      {{end}}
      </div>
    </div>

    <dialog id="tk-revoke-dlg" class="tk-dlg">
      <h3>{{.T.tokenRevoke}} - <span id="tk-revoke-name"></span></h3>
      <p class="tk-warn">{{.T.tokenRevokeConfirm}}</p>
      <form method="post" action="/profile/tokens">
        <input type="hidden" name="id" id="tk-revoke-id">
        <div class="tk-dlg-actions">
          <button type="button" class="tk-ghost" id="tk-revoke-cancel">{{.T.cancel}}</button>
          <button type="submit" name="action" value="revoke" class="danger">{{.T.tokenRevoke}}</button>
        </div>
      </form>
    </dialog>
    {{end}}
    <p class="back"><a href="/profile/security">{{.T.back}}</a></p>
    <script>
    (() => {
      const dlg = document.getElementById('tk-create-dlg');
      const open = document.getElementById('tk-open');
      if (dlg && open) {
        open.addEventListener('click', () => dlg.showModal());
        const cancel = document.getElementById('tk-cancel');
        if (cancel) cancel.addEventListener('click', () => dlg.close());
      }
      const rev = document.getElementById('tk-revoke-dlg');
      if (rev) {
        const idIn = document.getElementById('tk-revoke-id');
        const nameEl = document.getElementById('tk-revoke-name');
        for (const b of document.querySelectorAll('[data-revoke]')) {
          b.addEventListener('click', () => {
            idIn.value = b.dataset.revoke;
            nameEl.textContent = b.dataset.name || '';
            rev.showModal();
          });
        }
        const rc = document.getElementById('tk-revoke-cancel');
        if (rc) rc.addEventListener('click', () => rev.close());
      }
      const reveal = document.getElementById('tk-reveal-dlg');
      if (reveal) {
        reveal.showModal();
        const done = document.getElementById('tk-done');
        if (done) done.addEventListener('click', () => reveal.close());
        const copy = document.getElementById('tk-copy');
        const val = document.getElementById('tk-value');
        if (copy && val) copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(val.textContent); }
          catch (e) {
            const rg = document.createRange(); rg.selectNodeContents(val);
            const sel = getSelection(); sel.removeAllRanges(); sel.addRange(rg);
            try { document.execCommand('copy'); } catch (e2) {}
            sel.removeAllRanges();
          }
          copy.classList.add('ok');
          setTimeout(() => copy.classList.remove('ok'), 1200);
        });
      }
    })();
    </script>
`

func (h *Handler) tokensSession(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
		return store.Session{}, false
	}
	if sess.Pending != "" {
		http.Redirect(w, r, "/"+sess.Pending, http.StatusSeeOther)
		return store.Session{}, false
	}
	if !h.st.APITokensAllowed(r.Context()) {
		http.NotFound(w, r)
		return store.Session{}, false
	}
	return sess, true
}

func (h *Handler) showTokens(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.tokensSession(w, r)
	if !ok {
		return
	}
	h.renderTokens(w, r, sess, "", "", http.StatusOK)
}

// sessionContextLabel is the "tenant" or "tenant - group" a token would carry.
func (h *Handler) sessionContextLabel(r *http.Request, sess store.Session) (label string, hasTenant bool) {
	if sess.TenantID == "" {
		return "", false
	}
	t, err := h.st.GetTenant(r.Context(), sess.TenantID)
	if err != nil {
		return "", false
	}
	label = t.Name
	if sess.GroupID != "" {
		if groups, err := h.st.MemberGroups(r.Context(), sess.TenantID, sess.UserID); err == nil {
			for _, g := range groups {
				if g.ID == sess.GroupID {
					label += " - " + g.Name
					break
				}
			}
		}
	}
	return label, true
}

func (h *Handler) renderTokens(w http.ResponseWriter, r *http.Request, sess store.Session, created, errMsg string, status int) {
	data := apiTokensData{flowChrome: h.flowData(r, "titleTokens"), Created: created, Error: errMsg}
	ctxLabel, hasTenant := h.sessionContextLabel(r, sess)
	data.Context = ctxLabel
	if !hasTenant {
		data.Context = h.tr(r, "tokenContextNone")
		data.NoTenant = true
	}
	t := messages[prefsOf(r, h.offeredLanguages()).Lang]
	for _, d := range apiTokenDurations {
		data.Durations = append(data.Durations, durationOption{Days: d.Days, Label: t[d.Label]})
	}
	if tokens, err := h.st.ListAPITokens(r.Context(), sess.UserID, store.PlaneData); err == nil {
		now := time.Now().Unix()
		for _, tok := range tokens {
			v := apiTokenView{ID: tok.ID, Name: tok.Name, Prefix: tok.Prefix, Enabled: tok.Enabled, Context: tok.TenantName}
			if v.Context == "" {
				v.Context = t["tokenContextNone"]
			}
			if tok.GroupName != "" {
				v.Context += " - " + tok.GroupName
			}
			if tok.ExpiresAt != 0 {
				if now >= tok.ExpiresAt {
					v.Expiry, v.Expired = t["expired"], true
				} else {
					v.Expiry = t["until"] + " " + time.Unix(tok.ExpiresAt, 0).Format("2006-01-02")
				}
			}
			if tok.LastUsedAt != 0 {
				v.LastUsed = t["lastUsed"] + " " + time.Unix(tok.LastUsedAt, 0).Format("2006-01-02")
			}
			data.Tokens = append(data.Tokens, v)
		}
	}
	writeFlow(w, apiTokensPage, data, status)
}

func (h *Handler) doTokens(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.tokensSession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch r.PostFormValue("action") {
	case "create":
		h.createToken(w, r, sess)
		return
	case "toggle":
		id := r.PostFormValue("id")
		for _, t := range h.userTokens(r, sess.UserID) {
			if t.ID == id {
				_, _ = h.st.SetAPITokenEnabled(r.Context(), sess.UserID, id, !t.Enabled)
				break
			}
		}
	case "revoke":
		_, _ = h.st.RevokeAPIToken(r.Context(), sess.UserID, r.PostFormValue("id"))
	}
	http.Redirect(w, r, "/profile/tokens", http.StatusSeeOther)
}

func (h *Handler) userTokens(r *http.Request, userID string) []store.APIToken {
	tokens, _ := h.st.ListAPITokens(r.Context(), userID, store.PlaneData)
	return tokens
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request, sess store.Session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if len(name) > 60 {
		name = name[:60]
	}
	if name == "" {
		h.renderTokens(w, r, sess, "", h.tr(r, "errTokenName"), http.StatusUnprocessableEntity)
		return
	}
	days, _ := strconv.Atoi(r.PostFormValue("days"))
	var expiresAt int64
	if days > 0 {
		expiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix()
	}
	secret, err := randToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := apiTokenClearPrefix + secret
	prefix := token[:12]
	if err := h.st.AddAPIToken(r.Context(), randomID(), sess.UserID, name,
		hashTrust(token), prefix, store.PlaneData, sess.TenantID, sess.GroupID, expiresAt); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.renderTokens(w, r, sess, token, "", http.StatusOK)
}

// apiTokenClearPrefix must match session.apiTokenPrefix (the resolver checks
// it before hashing) - kept here so the two packages never drift.
const apiTokenClearPrefix = "mk_"
