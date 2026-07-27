import { ApplicationConfig } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { MAT_BUTTON_TOGGLE_DEFAULT_OPTIONS } from '@angular/material/button-toggle';
import { MAT_FORM_FIELD_DEFAULT_OPTIONS } from '@angular/material/form-field';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { provideStore } from '@softwarity/store';
import { routes } from './app.routes';
import { authInterceptor } from './auth.interceptor';

// No animations provider: since v20.2 the animations package is deprecated —
// Material animates natively (animate.enter/animate.leave, plain CSS).
export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(withInterceptors([authInterceptor])),
    // Persist UI table preferences (sort, filters) in browser storage.
    provideStore(),
    // Every mat-form-field is outline by default (no per-field appearance).
    { provide: MAT_FORM_FIELD_DEFAULT_OPTIONS, useValue: { appearance: 'outline' } },
    // Button toggles never show a selection checkmark — it shifts the label and
    // breaks the layout; selection is conveyed by the fill alone.
    {
      provide: MAT_BUTTON_TOGGLE_DEFAULT_OPTIONS,
      useValue: { hideSingleSelectionIndicator: true, hideMultipleSelectionIndicator: true },
    },
  ],
};
