import { Component } from '@angular/core';

@Component({
  selector: 'app-requirements',
  imports: [],
  preserveWhitespaces: true,
  template: `
    <h2>Requirements</h2>

    <p>
      The product is specified before it is built: the full requirements document —
      functional and non-functional, with every structural decision recorded — lives in the
      repository as
      <a href="https://github.com/softwarity/meerkat/blob/main/requirements.md" target="_blank"
        rel="noopener"><code>requirements.md</code></a>
      (currently maintained in French). The highlights:
    </p>

    <table>
      <thead>
        <tr>
          <th>Area</th>
          <th>What Meerkat commits to</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Identity</td>
          <td>
            Meerkat is the application's identity referential. Local accounts, passwordless
            first (passkeys as a first-class factor, TOTP with trusted browsers, email OTP).
            Enterprise federation (OIDC, LDAP bind-only, SAML, Kerberos) is authentication
            only — roles never come from the IdP.
          </td>
        </tr>
        <tr>
          <td>Authorization</td>
          <td>
            Hierarchical roles, role groups per organization, per-route and per-endpoint rules
            posed on a per-service endpoint inventory (OpenAPI fetched or uploaded, or a
            <em>record mode</em> that discovers endpoints from real traffic).
          </td>
        </tr>
        <tr>
          <td>Multi-tenancy</td>
          <td>
            Organizations with OWNER/ADMIN/USER members, group modes, tenant selection at login
            and hot switching, hierarchical session TTLs and business-hours access windows.
          </td>
        </tr>
        <tr>
          <td>Routing</td>
          <td>
            A service catalog auto-discovered in the cluster (Kubernetes, Swarm, DNS) or
            declared by hand; routes reference services; canary weights, hot reload, and
            <strong>versioned configurations</strong>: duplicate, edit as draft, diff,
            switch atomically, roll back. A config file only seeds the very first start.
          </td>
        </tr>
        <tr>
          <td>App-oriented filters</td>
          <td>
            Base-href rewriting, head injection, user button, language selector, role-based
            CSS — served as standard Web Components into the proxied apps, whatever their
            framework.
          </td>
        </tr>
        <tr>
          <td>Quotas &amp; audit</td>
          <td>
            API quotas per route/service/endpoint and per consumer with standard 429
            semantics and a log-only calibration mode; an append-only audit log and traffic
            dashboards, all built into the console — no external tooling required.
          </td>
        </tr>
        <tr>
          <td>Zero dependency</td>
          <td>
            One Go binary, embedded storage (SQLite-class) by default; PostgreSQL only for HA
            clustering, with inter-node signaling over the database itself — no message
            broker.
          </td>
        </tr>
        <tr>
          <td>Editions</td>
          <td>
            Open-core in one repository and one binary: FSL-1.1-Apache-2.0 core (free for any
            internal/production use, converts to Apache-2.0 after two years), Enterprise
            features under <code>ee/</code> unlocked by an offline-validated license key.
          </td>
        </tr>
      </tbody>
    </table>

    <div class="callout">
      <strong>Design principle.</strong> The anti-pattern Meerkat exists to break: “install the
      gateway, then Prometheus, then Grafana, then write YAML for everything”. Here you launch
      one binary, configure in the console, export, and replay the export anywhere.
    </div>
  `,
})
export class RequirementsComponent {}
