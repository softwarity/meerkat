import { Component, computed, inject, input, LOCALE_ID, output } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatTooltipModule } from '@angular/material/tooltip';
import { TimezoneSelectComponent } from '@softwarity/timezone-select';
import { DateTime, Info } from 'luxon';
import { BusinessAccess, DayRange } from '../api.service';

// Working-hours editor with the inherit toggle (TENANT-04, archway's
// BusinessAccessCtrl pattern): while inherited, the fields are disabled and
// display the inherited value; switching off inheritance seeds the override
// from it. The timezone comes first (browser default): each DAY is a row whose
// hour ranges are set in that local timezone — several ranges per day (split
// days), the UTC equivalent as a hint under each. The server always evaluates
// in UTC. Rows start on the locale's first day of week. Controlled component —
// value in, every edit emits a fresh value.
@Component({
  selector: 'app-business-access-form',
  imports: [
    MatButtonModule,
    MatCheckboxModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSlideToggleModule,
    MatTooltipModule,
    TimezoneSelectComponent,
  ],
  styleUrl: './business-access-form.component.scss',
  templateUrl: './business-access-form.component.html',
})
export class BusinessAccessFormComponent {
  readonly value = input.required<BusinessAccess>();
  // What this level inherits from (the level above), used for display while
  // inherited and to seed an override. Absent at the top (global) level.
  readonly inherited = input<BusinessAccess>({ inherited: false });
  // topLevel = the global level: no level above, so no inherit toggle — the
  // fields are always editable.
  readonly topLevel = input(false);
  readonly valueChange = output<BusinessAccess>();

  private readonly locale = inject(LOCALE_ID);
  private readonly browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';

  // Full localized weekday names (Monday-first, matching the 1..7 ISO codes),
  // and the row order starting on the locale's first day of week.
  private readonly dayNames = Info.weekdays('long', { locale: this.locale });
  protected readonly weekDays = (() => {
    const start = Info.getStartOfWeek({ locale: this.locale }) || 1;
    return Array.from({ length: 7 }, (_, i) => ((start - 1 + i) % 7) + 1);
  })();

  protected dayLabel(d: number): string {
    const name = this.dayNames[d - 1] ?? String(d);
    return name.charAt(0).toLocaleUpperCase(this.locale) + name.slice(1);
  }

  protected readonly shown = computed<BusinessAccess>(() =>
    !this.topLevel() && this.value().inherited ? this.inherited() : this.value(),
  );
  protected readonly dim = computed(() => !this.topLevel() && this.value().inherited);
  protected readonly displayTz = computed(() => this.shown().timezone || this.browserTz);

  // A day's ranges, earliest first. Mutations address ranges by reference.
  protected rangesFor(day: number): DayRange[] {
    return (this.shown().days ?? [])
      .filter((r) => r.day === day)
      .sort((a, b) => a.from.localeCompare(b.from));
  }

  protected utcHint(r: DayRange): string {
    const tz = this.displayTz();
    return `${utcTime(r.from, tz)} – ${utcTime(r.to, tz)} UTC`;
  }

  protected inheritLabel(): string {
    const tz = this.inherited().timezone || 'UTC';
    return $localize`:@@Inherited_TZ:Inherited (${tz}:TZ:)`;
  }

  protected toggleInherited(inherited: boolean): void {
    if (inherited) {
      this.valueChange.emit({ inherited: true });
    } else {
      // Seed the override from the inherited value so editing starts from it;
      // an inherited value with no timezone lands on the browser's.
      const seed = this.inherited();
      this.valueChange.emit({ ...seed, timezone: seed.timezone || this.browserTz, inherited: false });
    }
  }

  protected patchTimezone(tz: string): void {
    this.emitDays(this.shown().days ?? [], tz);
  }

  protected toggleDay(day: number, open: boolean): void {
    const days = this.shown().days ?? [];
    this.emitDays(open ? [...days, { day, from: '09:00', to: '18:00' }] : days.filter((r) => r.day !== day));
  }

  protected patchRange(range: DayRange, key: 'from' | 'to', v: string): void {
    this.emitDays((this.shown().days ?? []).map((r) => (r === range ? { ...r, [key]: v } : r)));
  }

  protected addRange(day: number): void {
    const days = this.shown().days ?? [];
    const last = this.rangesFor(day).at(-1);
    this.emitDays([...days, { day, from: last?.to || '14:00', to: '23:59' }]);
  }

  protected removeRange(range: DayRange): void {
    this.emitDays((this.shown().days ?? []).filter((r) => r !== range));
  }

  // Every edit pins the effective timezone so the first change persists the
  // browser default the hours were entered in.
  private emitDays(days: DayRange[], tz = this.displayTz()): void {
    this.valueChange.emit({ ...this.shown(), timezone: tz, inherited: false, days });
  }
}

// "09:00" wall-clock today in tz → "HH:MM" in UTC (DST-correct for today).
function utcTime(time: string, tz: string): string {
  const [hour, minute] = time.split(':').map(Number);
  if (isNaN(hour) || isNaN(minute)) return '';
  const dt = DateTime.now().setZone(tz).set({ hour, minute });
  return dt.isValid ? dt.toUTC().toFormat('HH:mm') : '';
}
