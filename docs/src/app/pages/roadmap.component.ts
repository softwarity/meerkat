import { Component } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';

@Component({
  selector: 'app-roadmap',
  imports: [MatIconModule],
  preserveWhitespaces: true,
  styles: [
    `
      .status-icon {
        font-size: 18px;
        width: 18px;
        height: 18px;
        vertical-align: middle;
        margin-right: 3px;
      }
      .status-icon.ok {
        color: #3fb950;
      }
      .status-icon.soon {
        color: var(--accent-yellow);
      }
    `,
  ],
  template: `
    <h2>Roadmap</h2>

    <p>
      Meerkat is built specification-first: the requirements document is the contract, the code
      follows it. Current sequence:
    </p>

    <table>
      <thead>
        <tr>
          <th>Phase</th>
          <th>Content</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Specification</td>
          <td>Full requirements (functional, non-functional, decisions) in the open</td>
          <td><mat-icon class="status-icon ok">check_circle</mat-icon> ongoing, near-complete</td>
        </tr>
        <tr>
          <td>Foundations</td>
          <td>Go skeleton, EE tree + offline license validation, CI/CD, multi-arch image, this doc site</td>
          <td><mat-icon class="status-icon ok">check_circle</mat-icon> done</td>
        </tr>
        <tr>
          <td>Walking skeleton</td>
          <td>
            The critical path end to end: a route stored in embedded storage → predicate
            matching → reverse proxy → an HTML-injection filter → a session cookie
          </td>
          <td><mat-icon class="status-icon soon">pending</mat-icon> next</td>
        </tr>
        <tr>
          <td>Identity core</td>
          <td>Login flow, sessions, passkeys/TOTP, JWT to upstreams, user profile</td>
          <td><mat-icon class="status-icon soon">pending</mat-icon> planned</td>
        </tr>
        <tr>
          <td>Service catalog &amp; console</td>
          <td>Discovery, routes editor, versioned configurations, quotas &amp; audit</td>
          <td><mat-icon class="status-icon soon">pending</mat-icon> planned</td>
        </tr>
        <tr>
          <td>Dev mode</td>
          <td>plug integration: per-dev keys, service substitution, tester variants</td>
          <td><mat-icon class="status-icon soon">pending</mat-icon> planned</td>
        </tr>
      </tbody>
    </table>

    <div class="callout">
      <strong>Follow along.</strong> Everything happens in the
      <a href="https://github.com/softwarity/meerkat" target="_blank" rel="noopener">repository</a>
      — the requirements, the decisions and their reasons, the code.
    </div>
  `,
})
export class RoadmapComponent {}
