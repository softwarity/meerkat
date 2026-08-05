// Keeps every locale in step: its catalogue AND the build/serve configurations
// it needs to run.
//
//   npm run extract && npm run i18n:sync
//
// For each locale declared in angular.json, the units missing from its
// catalogue are added with the SOURCE text as their target. That is not a
// translation and does not pretend to be: it is what lets a locale build and
// ship before anyone has translated a word, so adding a language is a decision
// about the product rather than a build problem to solve first.
//
// Existing targets are never touched. A translator's work survives every run,
// which is the only way this can be part of the routine.
//
// The configurations are the other half, and the half that was forgotten:
// declaring a locale under i18n.locales is enough for a production build
// (`localize: true` takes them all) but NOT to run one. `ng serve
// --configuration=<code>` needs a serve configuration, which needs a build
// configuration, and polyglot reads exactly that list - eighteen locales came
// up "(no serve config)" and none of them could be opened in dev. Adding a
// language is one entry under i18n.locales; the rest belongs here.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const angularPath = join(root, 'angular.json');
const angular = JSON.parse(readFileSync(angularPath, 'utf8'));
const project = angular.projects.console;
const i18n = project.i18n;
const sourceLocale = typeof i18n.sourceLocale === 'string' ? i18n.sourceLocale : i18n.sourceLocale.code;

// The subPath of a locale is what it is served under, so it is also its
// baseHref. It defaults to the code (zh-Hans is served from /zh-Hans/).
function subPathOf(code, value) {
  if (code === sourceLocale) {
    const src = i18n.sourceLocale;
    return (typeof src === 'object' && src.subPath) || code;
  }
  return (value && typeof value === 'object' && value.subPath) || code;
}

{
  const build = project.architect.build.configurations;
  const serve = project.architect.serve.configurations;
  const added = [];
  for (const [code, value] of [[sourceLocale, null], ...Object.entries(i18n.locales || {})]) {
    const subPath = subPathOf(code, value);
    if (!build[code]) {
      build[code] = { localize: [code], baseHref: `/${subPath}/` };
      added.push(`build:${code}`);
    }
    if (!serve[code]) {
      serve[code] = { buildTarget: `console:build:development,${code}` };
      added.push(`serve:${code}`);
    }
  }
  if (added.length) {
    writeFileSync(angularPath, JSON.stringify(angular, null, 2) + '\n');
    console.log(`angular.json: +${added.length} configurations (${added.join(', ')})`);
  } else {
    console.log('angular.json: every locale can be built and served');
  }
}

const sourcePath = join(root, 'src/locale/messages.xlf');
const source = readFileSync(sourcePath, 'utf8');

// The units of the source file, keyed by id, kept as raw text: rewriting XML
// through a parser would reflow the whole file and turn every sync into an
// unreadable diff.
const units = new Map();
for (const m of source.matchAll(/( *)(<trans-unit id="([^"]+)"[^>]*>[\s\S]*?<\/trans-unit>)/g)) {
  units.set(m[3], { indent: m[1], body: m[2] });
}
if (units.size === 0) {
  console.error('no trans-unit found in messages.xlf — run `npm run extract` first');
  process.exit(1);
}

// A unit for a locale that has no translation yet: the source text stands in as
// the target, so the page reads in English rather than showing a message id.
function untranslated({ indent, body }) {
  const source = body.match(/<source>([\s\S]*?)<\/source>/);
  if (!source) return null;
  const withTarget = body.replace(/<\/source>/, `</source>\n${indent}  <target>${source[1]}</target>`);
  return indent + withTarget;
}

let touched = 0;
for (const [code, locale] of Object.entries(i18n.locales)) {
  const file = join(root, typeof locale === 'string' ? locale : locale.translation);
  let text;
  if (existsSync(file)) {
    text = readFileSync(file, 'utf8');
  } else {
    // A new locale starts as an empty catalogue in the same shape as the others.
    text = source
      .replace(/<file ([^>]*)source-language="[^"]*"/, `<file $1source-language="${sourceLocale}" target-language="${code}"`)
      .replace(/( *)<trans-unit id="[^"]+"[^>]*>[\s\S]*?<\/trans-unit>\n/g, '');
    console.log(`  ${code}: new catalogue`);
  }

  const have = new Set([...text.matchAll(/<trans-unit id="([^"]+)"/g)].map((m) => m[1]));
  const missing = [...units.entries()].filter(([id]) => !have.has(id));
  if (missing.length === 0) {
    console.log(`  ${code}: up to date`);
    continue;
  }
  const blocks = missing.map(([, u]) => untranslated(u)).filter(Boolean);
  const at = text.lastIndexOf('    </body>');
  if (at < 0) {
    console.error(`  ${code}: ${file} has no <body> to append to`);
    process.exit(1);
  }
  writeFileSync(file, text.slice(0, at) + blocks.join('\n') + '\n' + text.slice(at));
  console.log(`  ${code}: +${blocks.length} untranslated`);
  touched += blocks.length;
}

console.log(touched === 0 ? 'every catalogue was already in step' : `${touched} units added across the catalogues`);
