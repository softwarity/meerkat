package auth

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/softwarity/meerkat/internal/store"
)

// The <meerkat-user-button> web component (UIF): a self-contained vanilla
// custom element the gateway injects into UI routes' pages. It fetches its
// data (and localized labels) from /meerkat/user-button.json, and interacts
// with the gateway's own endpoints: profile, tenant switch, language and
// color-scheme cookies, logout. Everything is same-origin and offline-first.

// registerUserButton mounts the component's endpoints on the DATA plane.
func (h *Handler) registerUserButton(mux *http.ServeMux) {
	mux.HandleFunc("GET /meerkat/user-button.js", h.userButtonJS)
	mux.HandleFunc("GET /meerkat/user-button.json", h.userButtonJSON)
	mux.HandleFunc("GET /meerkat/page.js", h.pageJS)
}

func (h *Handler) pageJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(pageJS))
}

func (h *Handler) userButtonJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(userButtonJS))
}

type userButtonTenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// userButtonLink is one reachable UI route: the Applications submenu.
type userButtonLink struct {
	Name string `json:"name"`
	Href string `json:"href"`
}

type userButtonPayload struct {
	Authenticated bool               `json:"authenticated"`
	Username      string             `json:"username,omitempty"`
	Fullname      string             `json:"fullname,omitempty"`
	Email         string             `json:"email,omitempty"`
	Initials      string             `json:"initials,omitempty"`
	Avatar        string             `json:"avatar,omitempty"`
	TenantID      string             `json:"tenantId,omitempty"`
	TenantName    string             `json:"tenantName,omitempty"`
	Tenants       []userButtonTenant `json:"tenants,omitempty"`
	// The language SUBMENU is not here: it is the ROUTE's locales, carried by
	// the component's own `languages` attribute (a different level from the
	// flow-page languages that translate the menu LABELS below).
	// Apps: the UI routes this session may open (public + authenticated +
	// granted role-gated ones) - navigation between the fronted applications.
	Apps []userButtonLink `json:"apps,omitempty"`
	// Groups: exclusive mode (RBAC-03) with a real choice - the Group
	// submenu; GroupID is the active one.
	Groups  []userButtonTenant `json:"groups,omitempty"`
	GroupID string             `json:"groupId,omitempty"`
	// Roles are the session's EFFECTIVE role names in the active tenant,
	// filtered to class-safe tokens - what roles.js stamps on <body>.
	Roles  []string `json:"roles,omitempty"`
	Scheme string   `json:"scheme"`
	// SchemeImposed says the integrator settled the light/dark question
	// (THEME-05): the button wears that scheme, stops following the system and
	// the visitor's cookie, and drops its own switch. Without this it kept
	// reading the cookie on its own and stayed dark on a light-only install -
	// the one place the choice was supposed to be visible.
	SchemeImposed bool `json:"schemeImposed,omitempty"`
	// Issues turns the "Report an issue" panel on (ISSUE-01): the tracker
	// setting is enabled AND the caller is signed in. It travels here (this
	// payload is no-store) because the component JS is cached for 5 minutes.
	Issues bool `json:"issues,omitempty"`
	// DevDocs turns the Developer submenu on (DOCS-01): the caller holds the
	// dev capability, which is the whole gate. Same reason as Issues for
	// riding here: the JS is cached, this payload is not.
	DevDocs bool              `json:"devDocs,omitempty"`
	Labels  map[string]string `json:"labels"`
	// ThemeCSS carries the ACTIVE theme's tokens rescoped to :host - the
	// button wears the selected theme inside its shadow root, falling back to
	// system colors when a token is missing.
	ThemeCSS string `json:"themeCss"`
}

// userButtonJSON answers the component's data: who is signed in, which tenants
// they may switch to, the offered languages and the menu labels - all in the
// request's locale.
func (h *Handler) userButtonJSON(w http.ResponseWriter, r *http.Request) {
	offered := h.offeredLanguages()
	p := prefsOf(r, offered)
	t := messages[p.Lang]
	labels := map[string]string{
		"profile":      t["profile"],
		"signIn":       t["signIn"],
		"signOut":      t["signOut"],
		"languages":    t["languages"],
		"colorScheme":  t["colorScheme"],
		"tenant":       t["tenant"],
		"group":        t["group"],
		"applications": t["applications"],
		"developer":    t["developer"],
		"apiDocs":      t["apiDocs"],
		"schemeAuto":   t["schemeAuto"],
		"schemeLight":  t["schemeLight"],
		"schemeDark":   t["schemeDark"],
		"cancel":       t["cancel"],
	}
	for _, k := range []string{"openIssue", "issueDescription",
		"issueCaptureScreen", "issueCaptureHint", "issueIncludeConsole", "issueRecapture",
		"issueCrop", "issueApply", "issueReset", "issueRemove", "issueSend", "issueSending",
		"issueSent", "issueFailed", "issueTooLarge", "issueCaptureFailed",
		"issueDescriptionRequired", "issueContextNote",
		"devTools", "devUser", "devRoles", "devApply", "devExit", "devNote", "devFailed"} {
		labels[k] = t[k]
	}
	css, _ := h.chrome()
	// Lang/Labels are Meerkat's OWN strings, in a flow-page (embedded)
	// language - a different level from the route's forwarded locales, which
	// the component resolves itself from its `languages` attribute.
	scheme, imposed := p.Scheme, false
	if forced := h.imposedScheme(); forced != "" {
		scheme, imposed = forced, true
	}
	payload := userButtonPayload{
		Scheme: scheme, SchemeImposed: imposed, Labels: labels,
		ThemeCSS: strings.Replace(string(css), ":root", ":host", 1),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	sess, err := h.sm.Resolve(r.Context(), r)
	if err != nil || sess.Pending != "" {
		writeUserButtonJSON(w, payload)
		return
	}
	u, err := h.st.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		writeUserButtonJSON(w, payload)
		return
	}
	payload.Authenticated = true
	payload.Username = u.Username
	payload.Fullname = u.Fullname
	payload.Email = u.Email
	payload.Initials = initials(u)
	payload.Issues = h.issuesEnabled(r)
	payload.DevDocs = u.Dev
	if avatar, err := h.st.GetUserAvatar(r.Context(), sess.UserID); err == nil {
		payload.Avatar = avatar
	}
	if sess.TenantID != "" {
		if tenant, err := h.st.GetTenant(r.Context(), sess.TenantID); err == nil {
			payload.TenantID = tenant.ID
			payload.TenantName = tenant.Name
		}
	}
	if memberships, err := h.activeMemberships(r.Context(), sess.UserID); err == nil && len(memberships) > 1 {
		for _, m := range memberships {
			payload.Tenants = append(payload.Tenants, userButtonTenant{ID: m.TenantID, Name: m.TenantName})
		}
	}
	for _, l := range h.reachableLinks(r.Context(), sess) {
		payload.Apps = append(payload.Apps, userButtonLink(l))
	}
	if names, err := h.st.SessionRoleNames(r.Context(), sess.UserID, sess.TenantID, sess.GroupID); err == nil {
		for _, n := range names {
			if classToken.MatchString(n) {
				payload.Roles = append(payload.Roles, n)
			}
		}
	}
	// Exclusive mode with a real choice: the Group submenu (RBAC-03).
	if sess.TenantID != "" && h.st.EffectiveGroupMode(r.Context(), sess.TenantID) == store.GroupModeSingle {
		if groups, err := h.st.MemberGroups(r.Context(), sess.TenantID, sess.UserID); err == nil && len(groups) > 1 {
			payload.GroupID = sess.GroupID
			for _, g := range groups {
				payload.Groups = append(payload.Groups, userButtonTenant{ID: g.ID, Name: g.Name})
			}
		}
	}
	writeUserButtonJSON(w, payload)
}

func writeUserButtonJSON(w http.ResponseWriter, payload userButtonPayload) {
	b, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(b)
}

// userButtonJS is the component itself. Vanilla, shadow DOM, system colors
// (Canvas/CanvasText follow color-scheme), no external request beyond its own
// JSON. The two-word position's FIRST word is the anchored edge and decides
// the menu's opening direction: top-left drops the menu downward, left-top
// opens it to the right of the button.
const userButtonJS = `(() => {
  if (customElements.get('meerkat-user-button')) return;

  const COOKIE_LANG = 'MEERKAT_LANG', COOKIE_SCHEME = 'MEERKAT_SCHEME';
  const setCookie = (k, v) => { document.cookie = k + '=' + v + ';path=/;max-age=31536000;SameSite=Lax'; };
  const getCookie = (k) => (document.cookie.split('; ').find(c => c.startsWith(k + '=')) || '').split('=')[1] || '';
  const darkMedia = matchMedia('(prefers-color-scheme: dark)');
  const SCHEME_ICONS = { auto: '◐', light: '☀', dark: '☾' };
  const SCHEME_NEXT = { auto: 'light', light: 'dark', dark: 'auto' };
  // A locale's ENDONYM (its name in itself: fr -> Francais), the language-menu
  // convention; falls back to the raw code.
  const langName = (code) => {
    try {
      const n = new Intl.DisplayNames([code], { type: 'language' }).of(code);
      return n ? n.charAt(0).toUpperCase() + n.slice(1) : code;
    } catch { return code; }
  };

  class MeerkatUserButton extends HTMLElement {
    connectedCallback() {
      if (this.shadowRoot) return;
      this.attachShadow({ mode: 'open' });
      // The button ITSELF always honors the user's scheme choice (the cookie
      // set on the flow pages): the shadow's light-dark() theme tokens and
      // system colors follow the host's color-scheme. The PAGE is only
      // driven when the route offers the switch (scheme="select").
      this.applyScheme(getCookie(COOKIE_SCHEME) || 'auto');
      // In auto, follow the system live (attribute/class mechanisms included)
      // - unless the integrator settled it, which the payload tells us below.
      darkMedia.addEventListener('change', () => {
        if (this.schemeImposed) return;
        if ((getCookie(COOKIE_SCHEME) || 'auto') === 'auto') this.applyScheme('auto');
      });
      fetch('/meerkat/user-button.json', { credentials: 'same-origin' })
        .then(r => r.json())
        .then(data => {
          // The integrator settled light/dark: wear it, whatever the cookie or
          // the system say. Applied before rendering so the button never shows
          // one look and then swaps.
          if (data.schemeImposed) {
            this.schemeImposed = true;
            this.applyScheme(data.scheme);
          }
          // A dev on a UI route also asks whether a UI test runs here
          // (uisim.go) - the developer bar and the frame render from it.
          const route = this.getAttribute('route');
          if (data.authenticated && data.devDocs && route) {
            return fetch('/meerkat/dev-sim?route=' + encodeURIComponent(route), { credentials: 'same-origin' })
              .then(r => (r.ok ? r.json() : null))
              .catch(() => null)
              .then(sim => this.render(data, sim));
          }
          this.render(data, null);
        })
        .catch(() => {});
    }

    // Own shadow first - always; then, when the route offers the switch,
    // reflect the choice for the target application: the CSS color-scheme +
    // data-meerkat-scheme, plus the app's own mechanism - an attribute
    // (light/dark values) or a class pair - as configured on the route.
    applyScheme(v) {
      this.style.colorScheme = (v === 'light' || v === 'dark') ? v : '';
      if (this.getAttribute('scheme') !== 'select') return;
      const root = document.documentElement;
      if (v === 'light' || v === 'dark') {
        root.style.colorScheme = v;
        root.setAttribute('data-meerkat-scheme', v);
      } else {
        root.style.colorScheme = '';
        root.removeAttribute('data-meerkat-scheme');
      }
      const mech = this.getAttribute('scheme-mechanism');
      if (!mech) return;
      const light = this.getAttribute('scheme-light') || '', dark = this.getAttribute('scheme-dark') || '';
      const resolved = (v === 'light' || v === 'dark') ? v : (darkMedia.matches ? 'dark' : 'light');
      if (mech === 'attribute') {
        const attr = this.getAttribute('scheme-attribute');
        if (attr) root.setAttribute(attr, resolved === 'dark' ? dark : light);
      } else if (mech === 'class') {
        if (light) root.classList.remove(light);
        if (dark) root.classList.remove(dark);
        const cls = resolved === 'dark' ? dark : light;
        if (cls) root.classList.add(cls);
      }
    }

    render(data, sim) {
      const h = parseInt(this.getAttribute('height'), 10) || 24;
      const position = this.getAttribute('position') || 'top-right';
      const shape = this.getAttribute('shape') === 'square' ? 'square' : 'round';
      const namePos = this.getAttribute('name'); // 'before' | 'after' | null (hidden)
      const [edge, align] = position.split('-');
      // Per-corner gaps: pad-y from the top/bottom edge, pad-x from the side.
      const padY = parseInt(this.getAttribute('pad-y'), 10);
      const padX = parseInt(this.getAttribute('pad-x'), 10);

      // Four corners; the menu opens away from the anchored edge.
      const host = { [edge]: (isNaN(padY) ? 12 : padY) + 'px', [align]: (isNaN(padX) ? 12 : padX) + 'px' };
      const menuPlace =
        // A tight 3px: on a light page the button's surface blends into the
        // background and any real gap READS twice as large.
        (edge === 'top' ? 'top: calc(100% + 3px);' : 'bottom: calc(100% + 3px);') +
        (align === 'left' ? 'left: 0;' : 'right: 0;');
      const btnRadius = shape === 'round' ? '999px' : Math.max(4, Math.round(h * 0.18)) + 'px';
      const avatarRadius = shape === 'round' ? '50%' : Math.max(3, Math.round(h * 0.14)) + 'px';

      const L = data.labels || {};
      const auth = !!data.authenticated;
      // Issue reports (ISSUE-01): start collecting the console tail as soon
      // as we know the tracker is on - a report attaches the recent output.
      if (auth && data.issues) hookConsole();

      // Signed out: the button IS the sign-in action, no menu. Icon only in
      // the compact form (no username configured), icon + label otherwise.
      if (!auth) {
        const compact = !namePos;
        const ic = Math.round(h * 0.58);
        this.shadowRoot.innerHTML =
          '<style>' + (data.themeCss || '') + '</style>' +
          '<style>' +
          ':host { all: initial; color-scheme: light dark; position: fixed; z-index: 2147483000; ' + Object.entries(host).map(([k, v]) => k + ':' + v + ';').join('') + ' }' +
          '* { box-sizing: border-box; }' +
          '.btn { display: inline-flex; align-items: center; gap: .4em; height: ' + h + 'px;' +
          ' padding: 0 ' + (compact ? Math.max(3, Math.round((h - ic) / 2)) + 'px' : '.6em') + ';' +
          ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 25%, transparent)); border-radius: ' + btnRadius + '; cursor: pointer;' +
          ' background: var(--mk-surface-container, Canvas); color: var(--mk-on-surface, CanvasText); font-family: var(--mk-font, system-ui);' +
          ' font-size: ' + Math.max(11, Math.round(h * 0.42)) + 'px; }' +
          '.btn:hover { border-color: var(--mk-primary, color-mix(in srgb, CanvasText 45%, transparent)); }' +
          '.ic { width: ' + ic + 'px; height: ' + ic + 'px; }' +
          '</style>' +
          '<button class="btn" id="signin" title="' + esc(L.signIn) + '" aria-label="' + esc(L.signIn) + '">' +
          '<svg class="ic" viewBox="0 -960 960 960" fill="currentColor" aria-hidden="true"><path d="M480-120v-80h280v-560H480v-80h280q33 0 56.5 23.5T840-760v560q0 33-23.5 56.5T760-120H480Zm-80-160-55-58 102-102H120v-80h327L345-622l55-58 200 200-200 200Z"/></svg>' +
          (compact ? '' : '<span>' + esc(L.signIn) + '</span>') +
          '</button>';
        this.shadowRoot.getElementById('signin').addEventListener('click', () => {
          location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search);
        });
        return;
      }

      // Cascading submenus: a child panel FLIES OUT beside the menu, away
      // from the anchored side (menu on the right edge -> panel opens left),
      // vertically grown away from the anchored edge (menu above the button
      // -> panel grows upward). The parent row's chevron sits on the opening
      // side and points the actual direction.
      const flyLeft = align !== 'left';
      const chev = '<span class="chev">' + (flyLeft ? '&#8249;' : '&#8250;') + '</span>';
      const subMenu = (label, inner) =>
        '<div class="has-sub"><button class="item parent">' +
        (flyLeft ? chev : '') + '<span class="grow">' + esc(label) + '</span>' + (flyLeft ? '' : chev) +
        '</button><div class="sub">' + inner + '</div></div>';

      const items = [];
      if (auth) {
        // The head IS the profile link (one entry saved), and the 3-state
        // scheme button rides ITS line (another entry saved): auto -> light
        // -> dark, same glyphs as the flow pages' switcher.
        const schemeBtn = this.getAttribute('scheme') === 'select' && !data.schemeImposed
          ? '<button class="sw on" data-scheme-cycle="' + (SCHEME_NEXT[data.scheme] || 'light') +
            '" title="' + esc(L.colorScheme) + '">' + (SCHEME_ICONS[data.scheme] || '◐') + '</button>'
          : '';
        items.push('<div class="head-row"><a class="head" href="/profile" title="' + esc(L.profile) + '"><strong>' + esc(data.username) + '</strong>' +
          (data.tenantName ? '<span class="sub-line">' + esc(data.tenantName) + '</span>' : '') + '</a>' + schemeBtn + '</div>');
        // The fronted applications this session may open; the current one is
        // ticked (matched on its entry path).
        if ((data.apps || []).length) {
          items.push(subMenu(L.applications, data.apps.map(a => {
            const cur = a.href === '/' ? location.pathname === '/'
              : (location.pathname === a.href || location.pathname.startsWith(a.href + '/'));
            return '<a class="item" href="' + esc(a.href) + '"><span>' + esc(a.name) + '</span>' +
              (cur ? mark() : '') + '</a>';
          }).join('')));
        }
        if ((data.tenants || []).length > 1) {
          items.push(subMenu(L.tenant, data.tenants.map(t =>
            '<button class="item pick" data-tenant="' + esc(t.id) + '" ' +
            (t.id === data.tenantId ? 'disabled' : '') + '><span>' + esc(t.name) + '</span>' +
            (t.id === data.tenantId ? mark() : '') + '</button>').join('')));
        }
        // Exclusive group mode (RBAC-03): pick the ONE group whose roles apply.
        if ((data.groups || []).length) {
          items.push(subMenu(L.group, data.groups.map(g =>
            '<button class="item pick" data-group="' + esc(g.id) + '" ' +
            (g.id === data.groupId ? 'disabled' : '') + '><span>' + esc(g.name) + '</span>' +
            (g.id === data.groupId ? mark() : '') + '</button>').join('')));
        }
        // The language submenu offers this ROUTE's locales (the languages
        // attribute) - the application's own languages, not the gateway's.
        const langCodes = (this.getAttribute('languages') || '').split(',').filter(Boolean);
        // The active locale is resolved against THIS ROUTE's languages, the
        // same order the gateway uses server-side (cookie, then the browser's
        // Accept-Language, then the first): no flow-page level leaks in.
        const pickLang = (tag) => {
          const t = (tag || '').toLowerCase();
          return langCodes.find(c => c.toLowerCase() === t)
            || langCodes.find(c => c.split('-')[0].toLowerCase() === t.split('-')[0]) || '';
        };
        let activeLang = pickLang(getCookie(COOKIE_LANG));
        if (!activeLang) for (const nav of (navigator.languages || [navigator.language || ''])) {
          activeLang = pickLang(nav); if (activeLang) break;
        }
        if (!activeLang && langCodes.length) activeLang = langCodes[0];
        if (langCodes.length > 1) {
          items.push(subMenu(L.languages, langCodes.map(code =>
            '<button class="item pick" data-lang="' + esc(code) + '" ' +
            (code === activeLang ? 'disabled' : '') + '><span>' + esc(langName(code)) + '</span>' +
            (code === activeLang ? mark() : '') + '</button>').join('')));
        }
        // Developer submenu (DOCS-01): the API docs entry, when the docs are
        // exposed AND the caller holds the dev capability - more entries will
        // join it. The flag rides the payload, never this cached JS.
        if (data.devDocs) {
          // Second entry: the UI test mode (DEV-10), only on a proxied UI
          // route (the route attribute names it).
          items.push(subMenu(L.developer || 'Developer',
            '<a class="item" href="/meerkat/apidocs/"><span>' + esc(L.apiDocs || 'API docs') + '</span></a>' +
            (this.getAttribute('route')
              ? '<button class="item" id="devtools"><span>' + esc(L.devTools || 'UI test mode') + '</span>' +
                (sim && sim.active ? mark() : '') + '</button>'
              : '')));
        }
        // The issue tracker's entry point (ISSUE-01), only when the payload
        // says the feature is on - the flag never lives in this cached JS.
        if (data.issues) {
          items.push('<button class="item" id="issue"><span>' + esc(L.openIssue || 'Report an issue') + '</span></button>');
        }
        items.push('<hr>');
        items.push('<button class="item out" id="logout"><span>' + esc(L.signOut) + '</span></button>');
      }

      this.shadowRoot.innerHTML =
        '<style>' + (data.themeCss || '') + '</style>' +
        '<style>' +
        ':host { all: initial; color-scheme: light dark; position: fixed; z-index: 2147483000; ' + Object.entries(host).map(([k, v]) => k + ':' + v + ';').join('') + ' }' +
        '* { box-sizing: border-box; font-family: system-ui, sans-serif; }' +
        '.btn { display: flex; align-items: center; gap: .45em; height: ' + h + 'px;' +
        ' padding: 0 ' + (namePos === 'after' && auth ? '.55em' : '.15em') + ' 0 ' + (namePos === 'before' && auth ? '.55em' : '.15em') + ';' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 25%, transparent)); border-radius: ' + btnRadius + '; cursor: pointer;' +
        ' background: var(--mk-surface-container, Canvas); color: var(--mk-on-surface, CanvasText); font-family: var(--mk-font, system-ui);' +
        ' font-size: ' + Math.max(11, Math.round(h * 0.42)) + 'px; }' +
        '.btn:hover { border-color: var(--mk-primary, color-mix(in srgb, CanvasText 45%, transparent)); }' +
        '.avatar { width: ' + (h - 6) + 'px; height: ' + (h - 6) + 'px; border-radius: ' + avatarRadius + ';' +
        ' display: grid; place-items: center; background: var(--mk-primary, color-mix(in srgb, CanvasText 82%, Canvas)); color: var(--mk-on-primary, Canvas);' +
        ' font-weight: 700; font-size: ' + Math.max(9, Math.round(h * 0.34)) + 'px; object-fit: cover; }' +
        '.wrap { position: relative; }' +
        '.menu { position: absolute; ' + menuPlace + ' min-width: 210px; padding: 6px;' +
        ' background: var(--mk-surface-container, Canvas); color: var(--mk-on-surface, CanvasText);' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' font-family: var(--mk-font, system-ui); border-radius: var(--mk-radius, 10px);' +
        ' box-shadow: 0 8px 30px rgba(0,0,0,.25); display: none; z-index: 3; }' +
        '.menu.open { display: block; }' +
        '.head-row { display: flex; align-items: center; gap: 4px; padding-right: 6px; }' +
        '.head-row .head { flex: 1; min-width: 0; }' +
        '.head { padding: 8px 10px; display: grid; color: inherit; text-decoration: none; border-radius: 7px; cursor: pointer; }' +
        '.head:hover { background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        '.head .sub-line { font-size: .78em; opacity: .65; }' +
        '.item { display: flex; align-items: center; justify-content: space-between; gap: 10px; width: 100%;' +
        ' padding: 7px 10px; border: 0; border-radius: 7px; background: none; color: inherit; text-align: left;' +
        ' font-size: .9em; text-decoration: none; cursor: pointer; }' +
        '.item:hover:not(:disabled) { background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        '.item:disabled { cursor: default; opacity: .85; }' +
        '.item.out { color: var(--mk-error, color-mix(in srgb, red 70%, CanvasText)); }' +
        '.chev { opacity: .55; }' +
        '.grow { flex: 1; text-align: left; }' +
        // Flyout submenus: a sibling panel of the parent row, opening away
        // from the anchored side and growing away from the anchored edge.
        '.has-sub { position: relative; }' +
        '.has-sub > .sub { position: absolute; ' +
        (flyLeft ? 'right: calc(100% - 2px);' : 'left: calc(100% - 2px);') +
        (edge === 'top' ? ' top: -6px;' : ' bottom: -6px;') +
        ' min-width: 180px; max-height: 60vh; overflow-y: auto; padding: 6px; display: none;' +
        ' background: var(--mk-surface-container, Canvas); color: var(--mk-on-surface, CanvasText);' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' border-radius: var(--mk-radius, 10px); box-shadow: 0 8px 30px rgba(0,0,0,.25); z-index: 1; }' +
        '.has-sub:hover > .sub, .has-sub.open > .sub { display: block; }' +
        '.has-sub:hover > .parent, .has-sub.open > .parent { background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        '.sw { padding: 3px 10px; border: 1px solid transparent; border-radius: 999px; background: none;' +
        ' color: var(--mk-on-surface-variant, color-mix(in srgb, CanvasText 65%, transparent)); cursor: pointer; font-size: .85em; line-height: 1.4; }' +
        '.sw:hover { border-color: var(--mk-outline, color-mix(in srgb, CanvasText 25%, transparent)); }' +
        '.sw.on { color: var(--mk-primary, CanvasText); border-color: var(--mk-outline, color-mix(in srgb, CanvasText 25%, transparent));' +
        ' background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        'hr { border: 0; border-top: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 15%, transparent)); margin: 6px 4px; }' +
        '.mark { font-weight: 700; }' +
        // Issue panel (ISSUE-01): a non-blocking floating card - no backdrop,
        // the page stays usable; the open dropdown (z-index 3) beats it.
        '.ip { position: fixed; width: min(340px, calc(100vw - 16px)); z-index: 2;' +
        ' background: var(--mk-surface-container, Canvas); color: var(--mk-on-surface, CanvasText);' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' border-radius: var(--mk-radius, 10px); box-shadow: 0 12px 40px rgba(0,0,0,.3);' +
        ' font-family: var(--mk-font, system-ui); font-size: 13px; }' +
        '.ip-head { display: flex; align-items: center; justify-content: space-between; gap: 8px;' +
        ' padding: 8px 12px; cursor: move; touch-action: none; user-select: none; font-weight: 600;' +
        ' border-bottom: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 15%, transparent)); }' +
        '.ip-x { border: 0; background: none; color: inherit; cursor: pointer; padding: 3px;' +
        ' display: grid; place-items: center; border-radius: 6px; }' +
        '.ip-x:hover { background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        '.ip-body { display: grid; gap: 8px; padding: 10px 12px 12px; max-height: calc(100vh - 140px); overflow-y: auto; }' +
        '.ip-desc { width: 100%; resize: vertical; min-height: 64px; padding: 6px 8px; border-radius: 7px;' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' background: var(--mk-surface, Canvas); color: inherit; font: inherit; }' +
        '.ip-stage { position: relative; }' +
        '.ip-stage canvas { display: block; width: 100%; border-radius: 6px;' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent)); }' +
        '.ip-ov { position: absolute; inset: 0; cursor: crosshair; touch-action: none; }' +
        '.ip-sel { position: absolute; display: none; border: 1px dashed #fff; outline: 1px dashed #000;' +
        ' background: rgba(0,0,0,.15); pointer-events: none; }' +
        '.ip-tools { display: flex; flex-wrap: wrap; gap: 6px; }' +
        '.ip-tools button { padding: 5px 10px; border-radius: 7px; background: none; color: inherit;' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' cursor: pointer; font: inherit; font-size: .9em; }' +
        '.ip-tools button:hover { background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        '.ip-cap-hint { flex-basis: 100%; margin: 0; }' +
        '.ip-opt { display: flex; align-items: center; gap: 8px; font-size: .85em; cursor: pointer; user-select: none; }' +
        '.ip-opt input { margin: 0; accent-color: var(--mk-primary, CanvasText); }' +
        '.ip-note { margin: 0; font-size: .78em; opacity: .65; }' +
        '.ip-msg { margin: 0; font-size: .85em; color: var(--mk-error, color-mix(in srgb, red 70%, CanvasText)); }' +
        '.ip-actions { display: flex; justify-content: flex-end; }' +
        '.ip-send { padding: 6px 14px; border-radius: 7px; border: 1px solid transparent; cursor: pointer;' +
        ' background: var(--mk-primary, CanvasText); color: var(--mk-on-primary, Canvas); font: inherit; font-size: .9em; }' +
        '.ip-send:hover { filter: brightness(1.1); }' +
        '.ip-send:disabled { opacity: .6; cursor: default; }' +
        // Developer bar (DEV-10): a top-center strip driving the UI test
        // mode, collapsible to a small DEV tab; the frame marks every page
        // served under a simulated identity. Amber on purpose: NOT themed,
        // it must stand out on any application.
        '.db-frame { position: fixed; inset: 0; pointer-events: none; border: 3px solid #f59e0b; z-index: 1; }' +
        '.db { position: fixed; top: 0; left: 50%; transform: translateX(-50%); z-index: 2;' +
        ' display: flex; align-items: center; flex-wrap: wrap; gap: 8px; padding: 6px 10px;' +
        ' max-width: min(720px, calc(100vw - 20px));' +
        ' background: var(--mk-surface-container, Canvas); color: var(--mk-on-surface, CanvasText);' +
        ' border: 1px solid #f59e0b; border-top: 0; border-radius: 0 0 10px 10px;' +
        ' box-shadow: 0 8px 30px rgba(0,0,0,.25); font-family: var(--mk-font, system-ui); font-size: 12px; }' +
        '.db.min > *:not(.db-tab) { display: none; }' +
        // Collapsed, the bar body vanishes entirely: only the handle stays,
        // sliding up to the viewport edge.
        '.db.min { padding: 0; border: 0; box-shadow: none; }' +
        // The handle: a drawer pull hanging under the bar, CENTERED, so the
        // bar retracts around it without the handle jumping sideways.
        '.db-tab { position: absolute; top: 100%; left: 50%; transform: translateX(-50%);' +
        ' display: flex; align-items: center; gap: 5px; padding: 2px 10px; cursor: pointer; font: inherit;' +
        ' background: var(--mk-surface-container, Canvas); color: inherit;' +
        ' border: 1px solid #f59e0b; border-top: 0; border-radius: 0 0 8px 8px; }' +
        '.db-badge { background: #f59e0b; color: #1c1c22; font-weight: 700; border-radius: 4px; padding: 1px 6px; font-size: 11px; }' +
        '.db label { display: flex; align-items: center; gap: 5px; }' +
        // Scoped to the text input: a bare ".db input" would also stretch the
        // popup's checkboxes to this width.
        '.db .db-user { padding: 4px 6px; border-radius: 6px; font: inherit; color: inherit; width: 120px;' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' background: var(--mk-surface, Canvas); }' +
        '.db-dd { position: relative; }' +
        '.db-roles-btn { padding: 4px 10px; border-radius: 6px; font: inherit; color: inherit; cursor: pointer;' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' background: var(--mk-surface, Canvas); }' +
        // z-index: with auto, the bar's LATER flex items (the note) paint
        // over the popup's top - seen as a "transparent" panel start.
        '.db-pop { position: absolute; top: calc(100% + 6px); left: 0; min-width: 190px; max-height: 50vh;' +
        ' overflow-y: auto; padding: 6px; display: none; z-index: 1;' +
        ' background: var(--mk-surface-container, Canvas); color: var(--mk-on-surface, CanvasText);' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent));' +
        ' border-radius: 10px; box-shadow: 0 8px 30px rgba(0,0,0,.25); }' +
        '.db-pop.open { display: block; }' +
        '.db-opt { display: flex; align-items: center; gap: 7px; padding: 3px 6px; border-radius: 6px;' +
        ' cursor: pointer; font-size: 12px; }' +
        '.db-opt:hover { background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        '.db-opt input { margin: 0; accent-color: var(--mk-primary, CanvasText); }' +
        // margin-left auto: the actions sit apart, at the bar's right edge.
        '.db-apply { margin-left: auto; padding: 4px 12px; border-radius: 6px; border: 1px solid transparent; cursor: pointer;' +
        ' background: var(--mk-primary, CanvasText); color: var(--mk-on-primary, Canvas); font: inherit; }' +
        '.db-apply:disabled { opacity: .6; cursor: default; }' +
        '.db-exit { padding: 4px 10px; border-radius: 6px; background: none; cursor: pointer; font: inherit;' +
        ' color: var(--mk-error, color-mix(in srgb, red 70%, CanvasText));' +
        ' border: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 22%, transparent)); }' +
        '.db-note { flex-basis: 100%; margin: 0; font-size: .75rem; opacity: .65; line-height: 1.35; }' +
        '.db-err { flex-basis: 100%; margin: 0; font-size: .8rem; color: var(--mk-error, color-mix(in srgb, red 70%, CanvasText)); }' +
        '</style>' +
        '<div class="wrap">' +
        '<button class="btn" id="toggle" aria-haspopup="menu">' +
        (namePos === 'before' && auth ? '<span class="name">' + esc(data.username) + '</span>' : '') +
        (auth && data.avatar
          ? '<img class="avatar" src="' + esc(data.avatar) + '" alt="">'
          : '<span class="avatar">' + esc(auth ? (data.initials || '?') : '-') + '</span>') +
        (namePos === 'after' && auth ? '<span class="name">' + esc(data.username) + '</span>' : '') +
        '</button>' +
        '<div class="menu" id="menu" role="menu">' + items.join('') + '</div>' +
        '</div>';

      const menu = this.shadowRoot.getElementById('menu');
      const closeSubs = () => {
        for (const o of this.shadowRoot.querySelectorAll('.has-sub.open')) o.classList.remove('open');
      };
      this.shadowRoot.getElementById('toggle').addEventListener('click', (e) => {
        e.stopPropagation();
        closeSubs();
        menu.classList.toggle('open');
      });
      document.addEventListener('click', () => { closeSubs(); menu.classList.remove('open'); });
      menu.addEventListener('click', (e) => e.stopPropagation());

      // Flyout submenus: hover opens them (pure CSS); a click PINS them for
      // touch screens. Opening one - by hover or click - closes every other:
      // a single panel is ever visible.
      for (const box of this.shadowRoot.querySelectorAll('.has-sub')) {
        box.addEventListener('mouseenter', () => {
          for (const o of this.shadowRoot.querySelectorAll('.has-sub.open')) {
            if (o !== box) o.classList.remove('open');
          }
        });
        box.querySelector('.parent').addEventListener('click', () => {
          const was = box.classList.contains('open');
          closeSubs();
          if (!was) box.classList.add('open');
        });
      }

      // Switching tenant may land on the group choice (exclusive mode):
      // follow wherever the gateway redirected instead of a blind reload.
      for (const b of this.shadowRoot.querySelectorAll('[data-tenant]')) {
        b.addEventListener('click', () => {
          const body = new URLSearchParams({ tenant: b.dataset.tenant, next: location.pathname + location.search });
          fetch('/select-tenant', { method: 'POST', body, credentials: 'same-origin' })
            .then((res) => { location.href = res.redirected ? res.url : location.href; })
            .catch(() => location.reload());
        });
      }
      for (const b of this.shadowRoot.querySelectorAll('[data-group]')) {
        b.addEventListener('click', () => {
          const body = new URLSearchParams({ group: b.dataset.group, next: location.pathname + location.search });
          fetch('/select-group', { method: 'POST', body, credentials: 'same-origin' })
            .then(() => location.reload());
        });
      }
      for (const b of this.shadowRoot.querySelectorAll('[data-lang]')) {
        b.addEventListener('click', () => { setCookie(COOKIE_LANG, b.dataset.lang); location.reload(); });
      }
      // The scheme cycles IN PLACE - no re-render, the menu stays open.
      const cyc = this.shadowRoot.querySelector('[data-scheme-cycle]');
      if (cyc) cyc.addEventListener('click', () => {
        const v = cyc.dataset.schemeCycle;
        setCookie(COOKIE_SCHEME, v);
        this.applyScheme(v);
        cyc.textContent = SCHEME_ICONS[v] || '◐';
        cyc.dataset.schemeCycle = SCHEME_NEXT[v] || 'light';
      });
      const out = this.shadowRoot.getElementById('logout');
      if (out) out.addEventListener('click', () => {
        fetch('/logout', { method: 'POST', credentials: 'same-origin' }).then(() => { location.href = '/login'; });
      });
      // Open the issue panel: the menu closes, the panel floats free of it.
      const iss = this.shadowRoot.getElementById('issue');
      if (iss) iss.addEventListener('click', () => {
        closeSubs();
        menu.classList.remove('open');
        openIssuePanel(this.shadowRoot, L);
      });
      // The developer bar (DEV-10): the menu entry opens it for editing; an
      // ALREADY running test shows it on every page load, frame included.
      const dt = this.shadowRoot.getElementById('devtools');
      if (dt) dt.addEventListener('click', () => {
        closeSubs();
        menu.classList.remove('open');
        openDevBar(this.shadowRoot, data, this.getAttribute('route'), sim, false);
      });
      if (sim && sim.active) openDevBar(this.shadowRoot, data, this.getAttribute('route'), sim, true);

      function parent(id, text) {
        return '<button class="item parent" data-sub="' + id + '"><span>' + esc(text) + '</span><span class="chev">›</span></button>';
      }
      function mark() { return '<span class="mark">✓</span>'; }
    }
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // ---- Developer bar (DEV-10) ------------------------------------------

  // The UI test bar: browse THIS route as a simulated identity to SEE what a
  // role sees. A singleton in the shadow root; while a test runs it returns
  // on every page load - collapsed to a small DEV tab when the developer
  // tucked it away (remembered per tab) - with the amber frame around the
  // page. Apply pushes the simulation server-side then reloads: the very
  // page on screen is served as that identity.
  let devBar = null;
  function openDevBar(root, data, route, sim, fromLoad) {
    const L = data.labels || {};
    const active = !!(sim && sim.active);
    const lb = (k, d) => L[k] || d;
    let collapsed = false;
    try { collapsed = fromLoad && sessionStorage.getItem('mk-devbar-min') === '1'; } catch (e) { /* opaque storage */ }
    if (devBar && root.contains(devBar)) {
      devBar.classList.remove('min');
      try { sessionStorage.removeItem('mk-devbar-min'); } catch (e) { /* ditto */ }
      return;
    }
    if (active && !root.querySelector('.db-frame')) {
      const frame = document.createElement('div');
      frame.className = 'db-frame';
      root.appendChild(frame);
    }
    // Defaults: the developer THEMSELVES with their CURRENT roles checked -
    // the natural start is taking roles away one by one.
    const checked = new Set(active ? (sim.roles || []) : (data.roles || []));
    let catalogRoles = [];
    const bar = document.createElement('div');
    bar.className = 'db' + (collapsed ? ' min' : '');
    bar.innerHTML =
      '<button class="db-tab" title="' + esc(lb('devTools', 'UI test mode')) + '">' +
      '<span class="db-badge">DEV</span><span class="db-chev">' + (collapsed ? '▾' : '▴') + '</span></button>' +
      '<label><span>' + esc(lb('devUser', 'User')) + '</span>' +
      '<input class="db-user" list="db-users" value="' + esc(active ? sim.user : (data.username || '')) + '"></label>' +
      '<datalist id="db-users"></datalist>' +
      '<div class="db-dd"><button class="db-roles-btn"></button><div class="db-pop"></div></div>' +
      '<button class="db-apply">' + esc(lb('devApply', 'Apply')) + '</button>' +
      '<button class="db-exit">' + esc(active ? lb('devExit', 'Exit test') : lb('cancel', 'Cancel')) + '</button>' +
      '<p class="db-note">' + esc(lb('devNote',
        'A developer lens, not a privilege: it needs the dev capability, applies only to your own session on this application, and every call is flagged as a test to the backend and logged under your real name.')) +
      '</p><p class="db-err" hidden></p>';
    root.appendChild(bar);
    devBar = bar;

    const q = (s) => bar.querySelector(s);
    const err = (text) => { const e = q('.db-err'); e.textContent = text; e.hidden = !text; };
    const rolesLabel = () => {
      q('.db-roles-btn').textContent = lb('devRoles', 'Roles') + ' (' + checked.size + ') ▾';
    };
    // The role checklist: the catalog first, plus any checked stragglers
    // (a role of the running test that left the catalog stays visible).
    const renderRoles = () => {
      const pop = q('.db-pop');
      pop.innerHTML = '';
      const all = catalogRoles.slice();
      for (const r of checked) if (!all.includes(r)) all.push(r);
      for (const r of all) {
        const opt = document.createElement('label');
        opt.className = 'db-opt';
        const c = document.createElement('input');
        c.type = 'checkbox';
        c.checked = checked.has(r);
        c.addEventListener('change', () => {
          if (c.checked) checked.add(r); else checked.delete(r);
          rolesLabel();
        });
        const name = document.createElement('span');
        name.textContent = r;
        opt.append(c, name);
        pop.append(opt);
      }
      rolesLabel();
    };
    renderRoles();
    // Candidates come from the SAME catalog the dev swagger forges from
    // (dev-gated, same exposure switch). Failing quietly keeps the bar
    // usable: the checked set is still editable.
    fetch('/meerkat/apidocs/catalog.json', { credentials: 'same-origin' })
      .then(r => (r.ok ? r.json() : null))
      .then(cat => {
        if (!cat) return;
        catalogRoles = cat.roles || [];
        const dl = q('#db-users');
        for (const u of (cat.users || [])) {
          const o = document.createElement('option');
          o.value = u.name;
          dl.append(o);
        }
        renderRoles();
      })
      .catch(() => {});
    q('.db-roles-btn').addEventListener('click', () => q('.db-pop').classList.toggle('open'));
    // Same shadow-retargeting dance as the menu: inner clicks stop here (a
    // click on the checklist must not close it), outside clicks close.
    bar.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!e.target.closest('.db-dd')) q('.db-pop').classList.remove('open');
    });
    document.addEventListener('click', () => q('.db-pop').classList.remove('open'));
    q('.db-tab').addEventListener('click', () => {
      const min = bar.classList.toggle('min');
      q('.db-chev').textContent = min ? '▾' : '▴';
      try { sessionStorage.setItem('mk-devbar-min', min ? '1' : '0'); } catch (e) { /* opaque storage */ }
    });
    const apply = () => {
      const user = q('.db-user').value.trim();
      const btn = q('.db-apply');
      btn.disabled = true;
      err('');
      fetch('/meerkat/dev-sim', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ route: route, user: user, roles: Array.from(checked) })
      }).then(r => {
        if (!r.ok) return r.json().then(b => { throw new Error(b && b.error || ''); });
        location.reload();
      }).catch(e => {
        btn.disabled = false;
        err((e && e.message) || lb('devFailed', 'Could not update the test mode.'));
      });
    };
    q('.db-apply').addEventListener('click', apply);
    q('.db-user').addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
    q('.db-exit').addEventListener('click', () => {
      if (!active) {
        bar.remove();
        devBar = null;
        return;
      }
      fetch('/meerkat/dev-sim?route=' + encodeURIComponent(route), { method: 'DELETE', credentials: 'same-origin' })
        .then(() => location.reload());
    });
    // No autofocus: focusing a datalist input pops its suggestion list open
    // uninvited - the field is one click away when the dev wants it.
  }

  // ---- Issue reports (ISSUE-01) ----------------------------------------

  // The console ring buffer: installed only when the payload says the tracker
  // is on, so pages of a gateway with the feature off keep a pristine console.
  // The originals are always called - devtools output never changes - and the
  // hook itself may NEVER break the app (every push is fenced).
  let issueRing = null;
  function hookConsole() {
    if (issueRing) return;
    issueRing = [];
    const cut = (s) => String(s).slice(0, 500);
    const push = (level, text) => {
      issueRing.push({ level: level, at: new Date().toISOString(), text: cut(text) });
      if (issueRing.length > 150) issueRing.shift();
    };
    const fmt = (a) => {
      if (typeof a === 'string') return a;
      if (a instanceof Error) return (a.name || 'Error') + ': ' + a.message + (a.stack ? '\n' + cut(a.stack) : '');
      try { return JSON.stringify(a); } catch { try { return String(a); } catch { return '[unserializable]'; } }
    };
    for (const level of ['log', 'info', 'warn', 'error']) {
      const orig = console[level].bind(console);
      console[level] = (...args) => {
        try { push(level, args.map(fmt).join(' ')); } catch {}
        orig(...args);
      };
    }
    addEventListener('error', (e) => {
      push('error', (e.message || 'error') + ' @ ' + (e.filename || '?') + ':' + (e.lineno || 0));
    });
    addEventListener('unhandledrejection', (e) => { push('error', 'unhandledrejection: ' + fmt(e.reason)); });
  }

  // Byte budgets: the encoded screenshot, then the whole JSON body, must fit
  // under the gateway's 2 MiB cap with headroom.
  const ISSUE_MAX_SHOT = 1400000;
  const ISSUE_MAX_JSON = 1900000;

  // The floating report panel: a singleton card in the component's shadow
  // root. No backdrop - the page stays fully usable while it is open - and
  // the header drags it out of the way of the bug being reported.
  let issuePanel = null;
  function openIssuePanel(root, L) {
    const lb = (k, d) => L[k] || d;
    if (issuePanel) { issuePanel.querySelector('.ip-desc').focus(); return; }
    const canCapture = !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia);
    const p = document.createElement('div');
    p.className = 'ip';
    p.setAttribute('role', 'dialog');
    p.setAttribute('aria-label', lb('openIssue', 'Report an issue'));
    const xSvg = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>';
    p.innerHTML =
      '<div class="ip-head"><span>' + esc(lb('openIssue', 'Report an issue')) + '</span>' +
      '<button class="ip-x" title="' + esc(lb('cancel', 'Cancel')) + '">' + xSvg + '</button></div>' +
      '<div class="ip-body">' +
      '<textarea class="ip-desc" rows="4" placeholder="' + esc(lb('issueDescription', 'Describe the problem')) + '"></textarea>' +
      '<div class="ip-stage"></div>' +
      '<div class="ip-tools"></div>' +
      '<label class="ip-opt"><input type="checkbox" class="ip-console" checked><span>' +
      esc(lb('issueIncludeConsole', 'Attach recent console output')) + '</span></label>' +
      '<p class="ip-note">' + esc(lb('issueContextNote', 'The page address and browser details are attached to your report.')) + '</p>' +
      '<p class="ip-msg" hidden></p>' +
      '<div class="ip-actions"><button class="ip-send">' + esc(lb('issueSend', 'Send')) + '</button></div>' +
      '</div>';
    root.appendChild(p);
    issuePanel = p;
    p.style.left = Math.max(8, innerWidth - 356) + 'px';
    p.style.top = '72px';

    const q = (sel) => p.querySelector(sel);
    const desc = q('.ip-desc'), stage = q('.ip-stage'), tools = q('.ip-tools'),
      msgEl = q('.ip-msg'), send = q('.ip-send');
    const st = { full: null, shot: null, rect: null, busy: false };
    const msg = (text) => {
      msgEl.hidden = !text;
      msgEl.textContent = text || '';
    };
    const btn = (cls, label) => '<button class="' + cls + '">' + esc(label) + '</button>';
    const close = () => { p.remove(); issuePanel = null; };
    q('.ip-x').addEventListener('click', close);
    p.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });

    // Drag by the header (pointer capture keeps events flowing off-panel);
    // clamped so at least a grabbable corner always stays on screen.
    const head = q('.ip-head');
    head.addEventListener('pointerdown', (e) => {
      if (e.target.closest('button')) return;
      const r = p.getBoundingClientRect(), dx = e.clientX - r.left, dy = e.clientY - r.top;
      head.setPointerCapture(e.pointerId);
      const mv = (ev) => {
        p.style.left = Math.min(Math.max(ev.clientX - dx, 60 - r.width), innerWidth - 60) + 'px';
        p.style.top = Math.min(Math.max(ev.clientY - dy, 0), innerHeight - 40) + 'px';
      };
      const up = () => { head.removeEventListener('pointermove', mv); head.removeEventListener('pointerup', up); };
      head.addEventListener('pointermove', mv);
      head.addEventListener('pointerup', up);
    });

    // Wait for a frame that reflects the just-hidden panel: capture streams
    // emit on change, so two rVFC ticks; 300ms cap as universal fallback.
    const frameReady = (v) => new Promise((res) => {
      let done = false;
      const fin = () => { if (!done) { done = true; res(); } };
      if (v.requestVideoFrameCallback) v.requestVideoFrameCallback(() => v.requestVideoFrameCallback(fin));
      setTimeout(fin, 300);
    });

    // One-frame native capture. Called straight from a click (transient
    // activation required); Chrome-only dictionary members are ignored by the
    // other engines. NotAllowedError is a cancelled picker: benign silence.
    async function capture() {
      msg('');
      let stream;
      try {
        stream = await navigator.mediaDevices.getDisplayMedia(
          { video: true, audio: false, preferCurrentTab: true, selfBrowserSurface: 'include' });
      } catch (err) {
        if (!err || err.name !== 'NotAllowedError') msg(lb('issueCaptureFailed', 'Screen capture failed.'));
        return;
      }
      try {
        const v = document.createElement('video');
        v.srcObject = stream; v.muted = true; v.playsInline = true;
        await v.play();
        p.style.visibility = 'hidden'; // keep the panel out of its own shot
        await frameReady(v);
        const k = Math.min(1, 1920 / Math.max(v.videoWidth || 1, v.videoHeight || 1));
        const c = document.createElement('canvas');
        c.width = Math.max(1, Math.round((v.videoWidth || 1) * k));
        c.height = Math.max(1, Math.round((v.videoHeight || 1) * k));
        c.getContext('2d').drawImage(v, 0, 0, c.width, c.height);
        st.full = st.shot = c; st.rect = null;
        renderPreview();
      } catch { msg(lb('issueCaptureFailed', 'Screen capture failed.')); }
      finally {
        p.style.visibility = '';
        for (const t of stream.getTracks()) t.stop();
      }
    }

    const renderIdle = () => {
      st.full = st.shot = st.rect = null;
      stage.innerHTML = '';
      // ONE capture mode, the exact one (Francois's call): real pixels via
      // the native picker. A DOM re-render was tried and dropped - it can
      // erase the very glitch being reported. The hint under the button
      // reassures whoever shares a whole screen: nothing leaves the panel
      // before Send, and a crop step narrows the image first.
      tools.innerHTML = canCapture
        ? btn('ip-screen', lb('issueCaptureScreen', 'Capture the screen')) +
          '<p class="ip-note ip-cap-hint">' +
          esc(lb('issueCaptureHint', 'The capture stays in this panel until you send it; you can crop it to the relevant area first.')) +
          '</p>'
        : '';
      if (canCapture) q('.ip-screen').addEventListener('click', capture);
    };

    const renderPreview = () => {
      stage.innerHTML = '';
      stage.appendChild(st.shot);
      tools.innerHTML = btn('ip-crop', lb('issueCrop', 'Crop')) +
        (st.shot !== st.full ? btn('ip-reset', lb('issueReset', 'Reset')) : '') +
        btn('ip-retake', lb('issueRecapture', 'Retake')) +
        btn('ip-remove', lb('issueRemove', 'Remove'));
      q('.ip-crop').addEventListener('click', renderCrop);
      const rs = q('.ip-reset');
      if (rs) rs.addEventListener('click', () => { st.shot = st.full; renderPreview(); });
      q('.ip-retake').addEventListener('click', capture);
      q('.ip-remove').addEventListener('click', renderIdle);
    };

    // Crop: drag a rectangle on the displayed canvas; width and height scale
    // by the SAME factor (aspect preserved), so one ratio maps the selection
    // back to full resolution. A sub-8px drag is an accidental click.
    const renderCrop = () => {
      st.rect = null;
      stage.innerHTML = '';
      stage.appendChild(st.shot);
      const ov = document.createElement('div'); ov.className = 'ip-ov';
      const sel = document.createElement('div'); sel.className = 'ip-sel';
      ov.appendChild(sel);
      stage.appendChild(ov);
      tools.innerHTML = btn('ip-apply', lb('issueApply', 'Apply')) + btn('ip-back', lb('cancel', 'Cancel'));
      const cl = (v, lo, hi) => Math.min(Math.max(v, lo), hi);
      ov.addEventListener('pointerdown', (e) => {
        const r = ov.getBoundingClientRect();
        const x0 = cl(e.clientX - r.left, 0, r.width), y0 = cl(e.clientY - r.top, 0, r.height);
        ov.setPointerCapture(e.pointerId);
        const mv = (ev) => {
          const x1 = cl(ev.clientX - r.left, 0, r.width), y1 = cl(ev.clientY - r.top, 0, r.height);
          st.rect = { x: Math.min(x0, x1), y: Math.min(y0, y1),
            w: Math.abs(x1 - x0), h: Math.abs(y1 - y0), dw: r.width };
          sel.style.cssText = 'display:block;left:' + st.rect.x + 'px;top:' + st.rect.y +
            'px;width:' + st.rect.w + 'px;height:' + st.rect.h + 'px;';
        };
        const up = () => {
          ov.removeEventListener('pointermove', mv);
          ov.removeEventListener('pointerup', up);
          if (st.rect && (st.rect.w < 8 || st.rect.h < 8)) { st.rect = null; sel.style.display = 'none'; }
        };
        ov.addEventListener('pointermove', mv);
        ov.addEventListener('pointerup', up);
      });
      q('.ip-apply').addEventListener('click', () => {
        if (st.rect) {
          const k = st.shot.width / st.rect.dw;
          const sx = Math.round(st.rect.x * k), sy = Math.round(st.rect.y * k);
          const sw = Math.max(1, Math.round(st.rect.w * k)), sh = Math.max(1, Math.round(st.rect.h * k));
          const c = document.createElement('canvas');
          c.width = sw; c.height = sh;
          c.getContext('2d').drawImage(st.shot, sx, sy, sw, sh, 0, 0, sw, sh);
          st.shot = c; // st.full untouched: Reset restores the original
        }
        renderPreview();
      });
      q('.ip-back').addEventListener('click', renderPreview);
    };

    // JPEG only (a PNG screen grab easily blows the cap), encoded once at
    // send time. Quality steps down, then the canvas shrinks: a safety net,
    // the 1920px grab cap makes the first attempt fit in practice.
    const encodeShot = () => {
      if (!st.shot) return '';
      let c = st.shot, qy = 0.85;
      for (let i = 0; i < 6; i++) {
        const uri = c.toDataURL('image/jpeg', qy);
        if (Math.ceil(uri.length * 3 / 4) <= ISSUE_MAX_SHOT) return uri;
        if (qy > 0.55) { qy -= 0.15; } else {
          const d = document.createElement('canvas');
          d.width = Math.max(1, Math.round(c.width * 0.7));
          d.height = Math.max(1, Math.round(c.height * 0.7));
          d.getContext('2d').drawImage(c, 0, 0, d.width, d.height);
          c = d; qy = 0.7;
        }
      }
      return null;
    };

    send.addEventListener('click', () => {
      const text = desc.value.trim();
      if (!text) { msg(lb('issueDescriptionRequired', 'A description is required.')); desc.focus(); return; }
      if (st.busy) return;
      const shot = encodeShot();
      if (shot === null) { msg(lb('issueTooLarge', 'The screenshot is too large to send.')); return; }
      const body = {
        description: text,
        url: location.href,
        userAgent: navigator.userAgent,
        viewport: innerWidth + 'x' + innerHeight,
        screen: screen.width + 'x' + screen.height,
        dpr: devicePixelRatio || 1,
        language: navigator.language || '',
        console: q('.ip-console').checked ? (issueRing || []).slice() : []
      };
      if (shot) body.screenshot = shot;
      let json = JSON.stringify(body);
      while (json.length > ISSUE_MAX_JSON && body.console.length) {
        body.console.splice(0, Math.ceil(body.console.length / 2));
        json = JSON.stringify(body);
      }
      if (json.length > ISSUE_MAX_JSON) { msg(lb('issueTooLarge', 'The screenshot is too large to send.')); return; }
      st.busy = true;
      send.disabled = true;
      send.textContent = lb('issueSending', 'Sending...');
      fetch('/meerkat/issues', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' }, body: json
      }).then((res) => {
        if (!res.ok) throw new Error('http ' + res.status);
        // Send -> Sent -> close: once the report left there is nothing to
        // read here, the panel dismisses itself.
        send.textContent = lb('issueSent', 'Sent');
        setTimeout(close, 900);
      }).catch(() => {
        // Failure keeps everything: message, inputs, and a live Send button.
        msg(lb('issueFailed', 'Sending failed. Please try again.'));
        st.busy = false;
        send.disabled = false;
        send.textContent = lb('issueSend', 'Send');
      });
    });

    renderIdle();
    desc.focus();
  }

  customElements.define('meerkat-user-button', MeerkatUserButton);
})();
`

// classToken keeps role names usable as CSS classes/attribute values - a role
// with spaces or punctuation is silently left out of the page.
var classToken = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// pageJS stamps the session onto the page as this route configures: the
// EFFECTIVE roles (body classes, one body attribute, or a <meta>) and the
// user's identity (prefixed body attributes or <meta> tags) - so the
// application reads them with pure CSS/DOM, no SDK.
const pageJS = `(() => {
  const s = document.currentScript;
  const cfg = (s && s.dataset) || {};
  const setMeta = (name, content) => {
    let m = document.querySelector('meta[name="' + name.replace(/"/g, '') + '"]');
    if (!m) { m = document.createElement('meta'); m.setAttribute('name', name); document.head.appendChild(m); }
    m.setAttribute('content', content);
  };
  fetch('/meerkat/user-button.json', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(data => {
      const apply = () => {
        const body = document.body;
        if (!body) return;
        if (cfg.rolesMechanism) {
          const roles = data.roles || [];
          if (cfg.rolesMechanism === 'class') for (const role of roles) body.classList.add(role);
          else if (cfg.rolesMechanism === 'attribute') body.setAttribute(cfg.rolesAttribute || 'data-roles', roles.join(' '));
          else if (cfg.rolesMechanism === 'meta') setMeta(cfg.rolesAttribute || 'meerkat-roles', roles.join(' '));
        }
        if (cfg.userMechanism) {
          const info = { username: data.username, fullname: data.fullname, email: data.email, tenant: data.tenantName };
          for (const [key, value] of Object.entries(info)) {
            if (!value) continue;
            if (cfg.userMechanism === 'meta') setMeta((cfg.userPrefix || 'meerkat') + '-' + key, value);
            else body.setAttribute((cfg.userPrefix || 'data-meerkat') + '-' + key, value);
          }
        }
      };
      if (document.body) apply();
      else addEventListener('DOMContentLoaded', apply);
    })
    .catch(() => {});
})();
`
