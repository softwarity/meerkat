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

// Page is the /apidocs/ shell: brand header, spec picker, swagger mount.
//
//go:embed page.html
var Page []byte

// AdminSpec describes Meerkat's own admin API (the first entry of the list).
//
//go:embed meerkat-admin.json
var AdminSpec []byte
