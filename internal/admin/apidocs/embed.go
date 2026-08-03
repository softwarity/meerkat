// Package apidocs carries the embedded API-docs page: the vendored swagger-ui
// assets (see tools/fetch-swagger-ui.py — offline-first, nothing is ever
// loaded from a CDN), the Sentinel's Watch skin posed on top of them, and the
// OpenAPI description of Meerkat's own admin API.
package apidocs

import _ "embed"

// BundleJS is the swagger-ui JavaScript bundle (vendored, Apache-2.0 — the
// LICENSE and NOTICE files live next to it in dist/).
//
//go:embed dist/swagger-ui-bundle.js
var BundleJS []byte

// CSS is swagger-ui's stock stylesheet; Skin overrides it.
//
//go:embed dist/swagger-ui.css
var CSS []byte

// Skin restyles swagger-ui to the console's Sentinel's Watch look.
//
//go:embed skin.css
var Skin []byte

// Page is the /apidocs/ shell: brand header, spec picker, swagger mount,
// credentialed Try it out.
//
//go:embed page.html
var Page []byte

// DevPage is the DATA-plane developer shell (/meerkat/apidocs): the routes'
// specs plus a bar forging the Try-it-out identity through THREE EXCLUSIVE
// modes (user, groups, roles). Entering a mode clears the others; the user
// mode offers a group flyout in an exclusive tenant (hover-bridged over the
// gap, and click pins it open). A status readout shows the
// effective identity (roles listed in a column aligned with the other values),
// and the gateway user button is pulled into the bar flow so it aligns. The
// gateway injects the ACTIVE theme before </head> at serve time. ASCII only.
//
//go:embed devpage.html
var DevPage []byte

// AdminSpec describes Meerkat's own admin API (the first entry of the list).
//
//go:embed meerkat-admin.json
var AdminSpec []byte
