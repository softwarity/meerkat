import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-about',
  imports: [RouterLink],
  preserveWhitespaces: true,
  styles: [
    `
      pre {
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 14px 16px;
        overflow-x: auto;

        code {
          font-family: 'Courier New', Consolas, monospace;
          font-size: 0.9em;
          color: var(--text-primary);
        }
      }
    `,
  ],
  template: `
    <h2>About</h2>

    <div class="callout warn">
      <strong>Specification phase.</strong> Meerkat is being designed in the open — the full
      requirements document lives in the repository and every structural decision is recorded
      there. Implementation starts with a Go walking skeleton. See the
      <a routerLink="/roadmap">roadmap</a>.
    </div>

    <p>
      Meerkat is an <strong>app-gateway</strong> — a gateway built to serve an
      <em>application</em>, not to expose APIs to third parties. It is the single entry point of
      an enterprise internal application composed of many services, and it takes charge of
      everything those services should never have to reimplement:
    </p>

    <ul>
      <li>
        <strong>Authentication</strong> — login pages served by the gateway, passwordless first
        (passkeys, TOTP, email OTP); enterprise methods (OIDC, LDAP, SAML) supported for
        authentication <em>only</em>.
      </li>
      <li>
        <strong>Authorization</strong> — roles and role groups live in Meerkat, enforced per
        route and per endpoint (from the service's OpenAPI spec, an uploaded one, or a recorded
        session).
      </li>
      <li>
        <strong>Multi-tenancy</strong> — organizations, members, groups, tenant switching,
        per-tenant session policies.
      </li>
      <li>
        <strong>Routing</strong> — a service catalog discovered in the cluster, dynamic routes
        edited hot, versioned configurations you can duplicate, diff, switch and roll back.
      </li>
      <li>
        <strong>Quotas, audit &amp; observability</strong> — built into the console. No
        Prometheus, no Grafana, no YAML required.
      </li>
      <li>
        <strong>Dev mode</strong> — with <a href="https://github.com/softwarity/plug"
        target="_blank" rel="noopener">plug</a>, a developer's workstation joins the cluster and
        substitutes a deployed service for their own traffic; testers opt in to try a dev's
        variant. See <a routerLink="/dev-mode">Dev mode</a>.
      </li>
    </ul>

    <p>
      Your services stay lean: they receive requests already authenticated, carrying a signed
      JWT with identity, roles and tenant. And the whole gateway is
      <strong>one binary with zero dependency</strong> — embedded storage by default, an
      external database only when you want a HA cluster.
    </p>

    <h3>Try it (once it exists)</h3>
    <pre><code>docker run -p 8080:8080 ghcr.io/softwarity/meerkat</code></pre>

    <h3>Why “Meerkat”?</h3>
    <p>
      The meerkat is nature's sentinel: it stands guard at the burrow entrance and raises the
      alert, so the rest of the colony can work without worrying about anything. That is exactly
      what this gateway does for your services. Even the plug tunnel fits the picture — it is
      how a developer's machine digs its way into the burrow. And since a group of meerkats is
      called a <em>mob</em>, you already know what to call a cluster of Meerkat nodes.
    </p>

    <h3>Lineage</h3>
    <p>
      Meerkat is the successor of
      <a href="https://github.com/softwarity/archway" target="_blank" rel="noopener">Archway</a>
      (Spring Cloud Gateway, MongoDB, Angular), rebuilt from the ground up in Go on the lessons
      of that first implementation — everything it did well is kept, everything it left on the
      table (rate limiting, built-in audit, zero-dependency startup) is a requirement this time.
    </p>
  `,
})
export class AboutComponent {}
