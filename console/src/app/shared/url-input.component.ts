import { Component, ElementRef, Input, computed, inject, input, output, signal } from '@angular/core';
import { MatFormFieldControl } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { Subject } from 'rxjs';

const SCHEME = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/;

// A custom MatFormFieldControl for a URL: a protocol select, "://", and the
// host/path, living together inside the parent's <mat-form-field> as ONE
// control (label, outline, focus all come from the parent). Signal-driven.
// It cannot be a Signal-Forms FormValueControl at the same time (both reserve a
// `value` member with incompatible types), so it binds through [(value)] on the
// form's value signal instead of [formField]. The bound value is a whole URL
// ("https://svc:8080"); pasting a full URL into the host splits its scheme off.
@Component({
  selector: 'app-url-input',
  imports: [MatSelectModule, MatInputModule],
  providers: [{ provide: MatFormFieldControl, useExisting: UrlInputComponent }],
  host: {
    class: 'app-url-input',
    '[id]': 'id',
    '[attr.aria-describedby]': 'describedBy()',
    '(focusin)': 'onFocusIn()',
    '(focusout)': 'onFocusOut($event)',
  },
  styleUrl: './url-input.component.scss',
  templateUrl: './url-input.component.html',
})
export class UrlInputComponent implements MatFormFieldControl<string> {
  private static seq = 0;
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);

  // ── MatFormFieldControl surface ────────────────────────────────────────────
  readonly stateChanges = new Subject<void>();
  readonly id = `app-url-input-${UrlInputComponent.seq++}`;
  readonly controlType = 'app-url-input';
  readonly ngControl = null;
  readonly placeholder = '';
  readonly required = false;
  readonly disabled = false;
  readonly errorState = false;

  private readonly _describedBy = signal('');
  protected readonly describedBy = computed(() => this._describedBy() || null);
  private _focused = false;

  get focused(): boolean {
    return this._focused;
  }
  get empty(): boolean {
    return !this.rest();
  }
  get shouldLabelFloat(): boolean {
    return this._focused || !this.empty;
  }

  setDescribedByIds(ids: string[]): void {
    this._describedBy.set(ids.join(' '));
  }
  onContainerClick(): void {
    this.host.nativeElement.querySelector('input')?.focus();
  }
  protected onFocusIn(): void {
    if (!this._focused) {
      this._focused = true;
      this.stateChanges.next();
    }
  }
  protected onFocusOut(e: FocusEvent): void {
    if (!this.host.nativeElement.contains(e.relatedTarget as Node | null)) {
      this._focused = false;
      this.stateChanges.next();
    }
  }

  // ── value: two-way via [(value)] (or [value] + (valueChange)) ──────────────
  private readonly _value = signal('');
  @Input()
  get value(): string {
    return this._value();
  }
  set value(v: string | null) {
    this._value.set(v ?? '');
    this.stateChanges.next();
  }
  readonly valueChange = output<string>();

  // ── protocol / host split ──────────────────────────────────────────────────
  readonly protocols = input<string[]>(['https', 'http']);
  protected readonly protocol = computed(() => split(this._value()).proto ?? this.protocols()[0] ?? 'https');
  protected readonly rest = computed(() => split(this._value()).rest);
  // Keep an out-of-catalogue stored scheme selectable.
  protected readonly protoOptions = computed(() => {
    const list = this.protocols();
    const cur = this.protocol();
    return list.includes(cur) ? list : [cur, ...list];
  });

  protected setProtocol(p: string): void {
    this.commit(p, this.rest());
  }
  protected onInput(raw: string): void {
    const s = split(raw);
    if (s.proto) {
      this.commit(s.proto, s.rest);
    } else {
      this.commit(this.protocol(), raw);
    }
  }

  private commit(proto: string, rest: string): void {
    const v = rest ? `${proto}://${rest}` : '';
    this._value.set(v);
    this.valueChange.emit(v);
    this.stateChanges.next();
  }
}

function split(v: string): { proto: string | null; rest: string } {
  const m = SCHEME.exec(v ?? '');
  return m ? { proto: m[1].toLowerCase(), rest: m[2] } : { proto: null, rest: v ?? '' };
}
