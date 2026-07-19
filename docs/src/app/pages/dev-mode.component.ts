import { Component } from '@angular/core';

@Component({
  selector: 'app-dev-mode',
  imports: [],
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
    <h2>Dev mode</h2>

    <p>
      The problem every internal-application team knows: the cluster holds all the services
      <strong>and all the data</strong>, and that environment is hard — sometimes forbidden — to
      reproduce on a developer's machine. Meerkat's answer is not to duplicate the environment
      but to bring the workstation <strong>into the routing mesh</strong>, like a tenant
      restricted to routing, powered by
      <a href="https://github.com/softwarity/plug" target="_blank" rel="noopener">plug</a>.
    </p>

    <h3>How it will work</h3>
    <p>
      An admin flags a user as <code>dev</code>. The developer registers a public key on their
      Meerkat account, then launches their service locally through plug:
    </p>

    <pre><code>plug -p cluster --service user-mng-service npm run start</code></pre>

    <ul>
      <li>
        <strong>Workstation → cluster</strong>: the local process resolves and reaches the
        cluster services as if it ran inside the cluster, with the developer's identity and
        roles (plug's original behaviour).
      </li>
      <li>
        <strong>Cluster → workstation</strong>: <code>--service</code> declares a
        <strong>substitution</strong> — for the developer's variant (<em>devname</em>), traffic
        to <code>user-mng-service</code> is routed through the reverse tunnel to the local
        process, which is seen, inbound and outbound, as a full member of the cluster. Every
        route referencing the service follows automatically.
      </li>
      <li>
        <strong>Testers opt in</strong>: users holding the <code>TESTER</code> role get a menu
        after login listing the devs with plugged services; picking one routes their traffic
        through that dev's variant — reversibly, with a visible indicator.
      </li>
      <li>
        <strong>Scoped and audited</strong>: by default only the developer's own traffic uses
        the substitution; it lives as long as the plug session and vanishes when the process
        stops.
      </li>
    </ul>

    <div class="callout">
      <strong>Today, plug's transport is trust-based</strong> (a shared embedded key — fine for
      the trusted clusters it targets). The Meerkat integration adds per-developer key
      authentication so a substitution is always attributable to the developer who owns it.
      This evolution is developed on a dedicated branch of plug, aiming for a
      backward-compatible plug v2.
    </div>
  `,
})
export class DevModeComponent {}
