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
	// granted role-gated ones) — navigation between the fronted applications.
	Apps []userButtonLink `json:"apps,omitempty"`
	// Groups: exclusive mode (RBAC-03) with a real choice — the Group
	// submenu; GroupID is the active one.
	Groups  []userButtonTenant `json:"groups,omitempty"`
	GroupID string             `json:"groupId,omitempty"`
	// Roles are the session's EFFECTIVE role names in the active tenant,
	// filtered to class-safe tokens — what roles.js stamps on <body>.
	Roles  []string          `json:"roles,omitempty"`
	Scheme string            `json:"scheme"`
	Labels map[string]string `json:"labels"`
	// ThemeCSS carries the ACTIVE theme's tokens rescoped to :host — the
	// button wears the selected theme inside its shadow root, falling back to
	// system colors when a token is missing.
	ThemeCSS string `json:"themeCss"`
}

// userButtonJSON answers the component's data: who is signed in, which tenants
// they may switch to, the offered languages and the menu labels — all in the
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
		"schemeAuto":   t["schemeAuto"],
		"schemeLight":  t["schemeLight"],
		"schemeDark":   t["schemeDark"],
	}
	css, _ := h.chrome()
	// Lang/Labels are Meerkat's OWN strings, in a flow-page (embedded)
	// language — a different level from the route's forwarded locales, which
	// the component resolves itself from its `languages` attribute.
	payload := userButtonPayload{
		Scheme: p.Scheme, Labels: labels,
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
      // In auto, follow the system live (attribute/class mechanisms included).
      darkMedia.addEventListener('change', () => {
        if ((getCookie(COOKIE_SCHEME) || 'auto') === 'auto') this.applyScheme('auto');
      });
      fetch('/meerkat/user-button.json', { credentials: 'same-origin' })
        .then(r => r.json())
        .then(data => this.render(data))
        .catch(() => {});
    }

    // Own shadow first — always; then, when the route offers the switch,
    // reflect the choice for the target application: the CSS color-scheme +
    // data-meerkat-scheme, plus the app's own mechanism — an attribute
    // (light/dark values) or a class pair — as configured on the route.
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

    render(data) {
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
        (edge === 'top' ? 'top: calc(100% + 8px);' : 'bottom: calc(100% + 8px);') +
        (align === 'left' ? 'left: 0;' : 'right: 0;');
      const btnRadius = shape === 'round' ? '999px' : Math.max(4, Math.round(h * 0.18)) + 'px';
      const avatarRadius = shape === 'round' ? '50%' : Math.max(3, Math.round(h * 0.14)) + 'px';

      const L = data.labels || {};
      const auth = !!data.authenticated;

      // Signed out: the button IS the sign-in action, no menu. Icon only in
      // the compact form (no username configured), icon + label otherwise.
      if (!auth) {
        const compact = !namePos;
        const ic = Math.round(h * 0.58);
        this.shadowRoot.innerHTML =
          '<style>' + (data.themeCss || '') + '</style>' +
          '<style>' +
          ':host { position: fixed; z-index: 2147483000; ' + Object.entries(host).map(([k, v]) => k + ':' + v + ';').join('') + ' }' +
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
        // The head IS the profile link (one entry saved).
        items.push('<a class="head" href="/profile" title="' + esc(L.profile) + '"><strong>' + esc(data.username) + '</strong>' +
          (data.tenantName ? '<span class="sub-line">' + esc(data.tenantName) + '</span>' : '') + '</a>');
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
        // attribute) — the application's own languages, not the gateway's.
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
        if (this.getAttribute('scheme') === 'select') {
          // ONE 3-state button (auto -> light -> dark), same glyphs as the
          // flow pages' switcher.
          items.push('<div class="schemes"><span class="sc-label">' + esc(L.colorScheme) + '</span>' +
            '<button class="sw on" data-scheme-cycle="' + (SCHEME_NEXT[data.scheme] || 'light') +
            '" title="' + esc(L.colorScheme) + '">' + (SCHEME_ICONS[data.scheme] || '◐') + '</button></div>');
        }
        items.push('<hr>');
        items.push('<button class="item out" id="logout"><span>' + esc(L.signOut) + '</span></button>');
      }

      this.shadowRoot.innerHTML =
        '<style>' + (data.themeCss || '') + '</style>' +
        '<style>' +
        ':host { position: fixed; z-index: 2147483000; ' + Object.entries(host).map(([k, v]) => k + ':' + v + ';').join('') + ' }' +
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
        ' box-shadow: 0 8px 30px rgba(0,0,0,.25); display: none; }' +
        '.menu.open { display: block; }' +
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
        '.schemes { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 7px 10px; }' +
        '.sc-label { font-size: .9em; }' +
        '.sw { padding: 3px 10px; border: 1px solid transparent; border-radius: 999px; background: none;' +
        ' color: var(--mk-on-surface-variant, color-mix(in srgb, CanvasText 65%, transparent)); cursor: pointer; font-size: .85em; line-height: 1.4; }' +
        '.sw:hover { border-color: var(--mk-outline, color-mix(in srgb, CanvasText 25%, transparent)); }' +
        '.sw.on { color: var(--mk-primary, CanvasText); border-color: var(--mk-outline, color-mix(in srgb, CanvasText 25%, transparent));' +
        ' background: var(--mk-surface-container-high, color-mix(in srgb, CanvasText 10%, transparent)); }' +
        'hr { border: 0; border-top: 1px solid var(--mk-outline, color-mix(in srgb, CanvasText 15%, transparent)); margin: 6px 4px; }' +
        '.mark { font-weight: 700; }' +
        '</style>' +
        '<div class="wrap">' +
        '<button class="btn" id="toggle" aria-haspopup="menu">' +
        (namePos === 'before' && auth ? '<span class="name">' + esc(data.username) + '</span>' : '') +
        (auth && data.avatar
          ? '<img class="avatar" src="' + esc(data.avatar) + '" alt="">'
          : '<span class="avatar">' + esc(auth ? (data.initials || '?') : '·') + '</span>') +
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
      // touch screens. Opening one — by hover or click — closes every other:
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
      // The scheme cycles IN PLACE — no re-render, the menu stays open.
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

      function parent(id, text) {
        return '<button class="item parent" data-sub="' + id + '"><span>' + esc(text) + '</span><span class="chev">›</span></button>';
      }
      function mark() { return '<span class="mark">✓</span>'; }
    }
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  customElements.define('meerkat-user-button', MeerkatUserButton);
})();
`

// classToken keeps role names usable as CSS classes/attribute values — a role
// with spaces or punctuation is silently left out of the page.
var classToken = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// pageJS stamps the session onto the page as this route configures: the
// EFFECTIVE roles (body classes, one body attribute, or a <meta>) and the
// user's identity (prefixed body attributes or <meta> tags) — so the
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
