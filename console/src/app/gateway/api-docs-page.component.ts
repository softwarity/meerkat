import { Component } from '@angular/core';

// API docs — the swagger-ui page the gateway serves at /apidocs/ (assets
// embedded in the binary, Sentinel's Watch skin), shown full-bleed in an
// iframe: swagger's invasive CSS stays fully isolated from Material, and the
// very same URL opens standalone in a tab (the page offers the pop-out).
@Component({
  selector: 'app-api-docs-page',
  styles: [
    `
      :host {
        display: block;
        height: 100%;
      }
      iframe {
        display: block;
        width: 100%;
        height: 100%;
        border: 0;
      }
    `,
  ],
  template: `<iframe src="/apidocs/" i18n-title="@@API_documentation" title="API documentation"></iframe>`,
})
export class ApiDocsPageComponent {}
