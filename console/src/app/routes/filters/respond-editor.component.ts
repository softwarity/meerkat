import { afterNextRender, Component, ElementRef, inject, input, model, output, signal, viewChild } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { Decoration, DecorationSet, EditorView, ViewPlugin, ViewUpdate } from '@codemirror/view';
import { EditorState, Range } from '@codemirror/state';
import { oneDark } from '@codemirror/theme-one-dark';
import { basicSetup } from 'codemirror';
import { ApiService } from '../../api.service';

// The template editor: colours, and an answer under the cursor.
//
// A plain <textarea> was not enough, and the reason is not decoration. Go
// template syntax is not guessable — {{if $i}},{{end}} to place a comma reads
// like line noise until someone explains it — so the editor has to do the
// explaining: actions stand out from the literal text, and the panel below
// shows what an application would actually receive, rendered by the gateway
// itself for a witness caller. Someone who cannot remember the syntax can
// still tell whether they got it right, which is the part that matters.

// ACTION matches one {{ … }}, DOT a .Field inside it, FUNC a leading function
// name, VAR a $variable. Deliberately shallow: this is highlighting, not
// parsing — the gateway owns the truth, and it answers in the panel below.
const ACTION = /\{\{[^}]*\}\}/g;
const INNER = /(\.[A-Za-z][A-Za-z0-9]*)|(\$[A-Za-z][A-Za-z0-9]*)|\b(json|join|wrap|range|if|else|end|with)\b|("[^"]*")/g;

const action = Decoration.mark({ class: 'tpl-action' });
const field = Decoration.mark({ class: 'tpl-field' });
const variable = Decoration.mark({ class: 'tpl-var' });
const fn = Decoration.mark({ class: 'tpl-fn' });
const str = Decoration.mark({ class: 'tpl-str' });

function decorate(view: EditorView): DecorationSet {
  const text = view.state.doc.toString();
  const ranges: Range<Decoration>[] = [];
  for (const m of text.matchAll(ACTION)) {
    const base = m.index ?? 0;
    ranges.push(action.range(base, base + m[0].length));
    for (const i of m[0].matchAll(INNER)) {
      const at = base + (i.index ?? 0);
      const deco = i[1] ? field : i[2] ? variable : i[3] ? fn : str;
      ranges.push(deco.range(at, at + i[0].length));
    }
  }
  // Sorted by CodeMirror (the `true`): the inner marks nest inside the action
  // that contains them, and hand-sorting two builders was how this first went
  // wrong.
  return Decoration.set(ranges, true);
}

const highlight = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet;
    constructor(view: EditorView) {
      this.decorations = decorate(view);
    }
    update(u: ViewUpdate) {
      if (u.docChanged || u.viewportChanged) this.decorations = decorate(u.view);
    }
  },
  { decorations: (v) => v.decorations },
);

@Component({
  selector: 'app-respond-editor',
  imports: [MatIconModule, MatTooltipModule],
  styles: [
    `
      :host {
        display: block;
      }
      .label {
        font-size: 0.75rem;
        color: var(--mat-sys-on-surface-variant);
        margin-bottom: 4px;
      }
      .editor {
        border: 1px solid var(--mat-sys-outline-variant);
        border-radius: 8px;
        overflow: hidden;
      }
      .editor:focus-within {
        border-color: var(--mat-sys-primary);
      }
      .cm-editor {
        background: var(--mat-sys-surface-container-lowest);
        font-family: var(--mk-mono);
        font-size: 0.82rem;
      }
      .cm-editor .cm-content {
        caret-color: var(--mat-sys-primary);
      }
      .cm-editor .cm-gutters {
        background: transparent;
        border: 0;
        color: var(--mat-sys-outline);
      }
      .cm-editor .cm-activeLine {
        background: color-mix(in srgb, var(--mat-sys-primary) 6%, transparent);
      }
      .out {
        margin-top: 8px;
        border-radius: 8px;
        padding: 8px 10px;
        background: var(--mat-sys-surface-container);
      }
      /* The rendered answer, in a <pre> of its own: it used to sit directly in
         a pre-wrap block, which printed the template's own indentation. */
      .out-body {
        margin: 0;
        font-family: var(--mk-mono);
        font-size: 0.78rem;
        line-height: 1.5;
        white-space: pre-wrap;
        word-break: break-word;
      }
      .out.err {
        background: color-mix(in srgb, var(--mat-sys-error) 12%, transparent);
        color: var(--mat-sys-error);
      }
      .out-head {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 0.74rem;
        color: var(--mat-sys-on-surface-variant);
        margin-bottom: 5px;
      }
      .out.err .out-head {
        color: var(--mat-sys-error);
      }
      mat-icon {
        font-size: 15px;
        width: 15px;
        height: 15px;
      }
    `,
  ],
  template: `
    <div class="label">Template</div>
    <div class="editor" #host></div>
    @if (error(); as e) {
      <div class="out err">
        <div class="out-head"><mat-icon>error_outline</mat-icon><span>This template cannot be saved</span></div>
        <pre class="out-body">{{ e }}</pre>
      </div>
    } @else if (output(); as o) {
      <div class="out">
        <div class="out-head">
          <mat-icon>play_arrow</mat-icon><span>What an application receives, for a caller named {{ callerName }}</span>
        </div>
        <pre class="out-body">{{ o }}</pre>
      </div>
    }
  `,
})
export class RespondEditorComponent {
  readonly value = model<string>('');
  readonly changed = output<string>();
  private readonly api = inject(ApiService);
  private readonly host = viewChild.required<ElementRef<HTMLDivElement>>('host');

  protected readonly output = signal('');
  protected readonly error = signal('');
  // Kept in step with routing.SampleIdentity: the name carries a quote and an
  // apostrophe on purpose, so a template that only works for well-behaved names
  // shows it here rather than in production.
  protected readonly callerName = `j"o'hn`;

  private view?: EditorView;
  private timer?: ReturnType<typeof setTimeout>;

  constructor() {
    afterNextRender(() => {
      this.view = new EditorView({
        state: EditorState.create({
          doc: this.value(),
          extensions: [
            // The same pair as the Add CSS / Add JavaScript dialog: one library
            // is not enough, it has to be one SETUP too, or the two editors of
            // the same product show different gutters.
            basicSetup,
            oneDark,
            highlight,
            EditorView.lineWrapping,
            EditorView.theme({
              '&': { maxHeight: '280px' },
              '.cm-scroller': { overflow: 'auto' },
              // The editable area fills the box, so clicking anywhere in it
              // places the cursor - five visible lines that only answer on the
              // first one read as a broken field.
              '.cm-content': { minHeight: '110px' },
            }),
            EditorView.updateListener.of((u) => {
              if (!u.docChanged) return;
              const text = u.state.doc.toString();
              this.value.set(text);
              this.changed.emit(text);
              this.schedulePreview(text);
            }),
          ],
        }),
        parent: this.host().nativeElement,
      });
      this.schedulePreview(this.value());
    });
  }

  // Debounced: the preview follows typing, it does not race it.
  private schedulePreview(body: string): void {
    clearTimeout(this.timer);
    if (!body.trim()) {
      this.output.set('');
      this.error.set('');
      return;
    }
    this.timer = setTimeout(() => {
      this.api.respondPreview(body).subscribe({
        next: (r) => {
          this.error.set(r.error ?? '');
          this.output.set(r.output ?? '');
        },
        error: () => undefined, // a preview that cannot be fetched says nothing
      });
    }, 400);
  }
}
