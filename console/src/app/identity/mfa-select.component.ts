import { Component, input, output } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';

// A tri-state second-factor override (MFA-04), mirroring the Session-TTL select:
// '' inherits the level above (whose resolved value is shown in the label),
// 'true' forces it required, 'false' forces it optional. Reused at the tenant
// and member levels.
@Component({
  selector: 'app-mfa-select',
  imports: [MatFormFieldModule, MatSelectModule],
  template: `
    <mat-form-field>
      <mat-label i18n="@@Two_factor">Two-factor</mat-label>
      <mat-select [value]="value()" (selectionChange)="valueChange.emit($event.value)">
        <mat-option value="">
          <ng-container i18n="@@Inherited_MFA">Inherited ({{ inheritedLabel() }})</ng-container>
        </mat-option>
        <mat-option value="true" i18n="@@MFA_required">Required</mat-option>
        <mat-option value="false" i18n="@@MFA_optional">Optional</mat-option>
      </mat-select>
    </mat-form-field>
  `,
})
export class MfaSelectComponent {
  readonly value = input.required<string>();
  // The effective value one level up, e.g. "Required" / "Optional".
  readonly inheritedLabel = input.required<string>();
  readonly valueChange = output<string>();
}
