import { Duration } from 'luxon';

// "PT8H" → "8 hours" / "8 heures" — ISO-8601 durations are stored, humans read
// their locale. Falls back to the raw code when the ISO string does not parse.
export function humanDuration(iso: string, locale: string): string {
  const d = Duration.fromISO(iso);
  return d.isValid ? d.reconfigure({ locale }).toHuman() : iso;
}
