// Editable theme tokens, mirroring the Go side (store.themeTokens).
export const CSS_VARS: Record<string, string> = {
  primary: '--mk-primary',
  onPrimary: '--mk-on-primary',
  night: '--mk-night',
  surface: '--mk-surface',
  onSurface: '--mk-on-surface',
  surfaceContainer: '--mk-surface-container',
  surfaceContainerHigh: '--mk-surface-container-high',
  onSurfaceVariant: '--mk-on-surface-variant',
  outline: '--mk-outline',
  error: '--mk-error',
};

export interface TokenGroup {
  label: string;
  tokens: { key: string; label: string }[];
}

export const TOKEN_GROUPS: TokenGroup[] = [
  {
    label: 'Accent',
    tokens: [
      { key: 'primary', label: 'Primary (signal / CTA)' },
      { key: 'onPrimary', label: 'On primary' },
      { key: 'night', label: 'Glow' },
    ],
  },
  {
    label: 'Surfaces',
    tokens: [
      { key: 'surface', label: 'Surface' },
      { key: 'surfaceContainer', label: 'Card' },
      { key: 'surfaceContainerHigh', label: 'Field' },
      { key: 'outline', label: 'Outline' },
    ],
  },
  {
    label: 'Text',
    tokens: [
      { key: 'onSurface', label: 'Text' },
      { key: 'onSurfaceVariant', label: 'Muted text' },
      { key: 'error', label: 'Error' },
    ],
  },
];
