#!/usr/bin/env python3
"""Self-host the console's web fonts (offline-first: the gateway must run with
NO internet). Fetches the woff2 files from Google Fonts into public/fonts/ and
regenerates src/styles/_fonts.scss with local @font-face rules. Run from
anywhere: `python3 console/tools/fetch-fonts.py` (needs internet ONCE, to fetch).

Latin subset only for the text fonts (covers EN/FR); Material Symbols ships its
full glyph set. Keep the CDN <link>s OUT of index.html — that is the whole point.
"""
import urllib.request, re, pathlib

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
# Fonts live under src/styles/ so Angular BUNDLES them (hashes + rewrites the
# url base-href/locale-correctly). A path like /fonts/** in public/ breaks under
# the i18n locale prefix (/en/, /fr/) — it 302s to the locale root.
CONSOLE = pathlib.Path(__file__).resolve().parent.parent
OUT = CONSOLE / "src" / "styles" / "fonts"
OUT.mkdir(parents=True, exist_ok=True)

# The design's fonts, exactly as index.html used to request them from the CDN.
TEXT = ("https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500"
        "&family=Bricolage+Grotesque:opsz,wght@12..96,400..800"
        "&family=JetBrains+Mono:wght@400;500&display=swap")
SYM = ("https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:"
       "opsz,wght,FILL,GRAD@20..48,400,0,0")


def get(url):
    return urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": UA}), timeout=45).read()


blocks = []


def parse(css, latin_only):
    for m in re.finditer(r'(?:/\*\s*([^*]+?)\s*\*/\s*)?@font-face\s*{([^}]*)}', css):
        comment, body = (m.group(1) or "").strip(), m.group(2)
        if latin_only and comment != "latin":
            continue
        fam = re.search(r"font-family:\s*'([^']+)'", body).group(1)
        sty = (re.search(r"font-style:\s*(\w+)", body) or [None, "normal"])[1]
        wgt = (re.search(r"font-weight:\s*([0-9 ]+)", body) or [None, "400"])[1].strip()
        url = re.search(r"url\((https://[^)]+\.woff2)\)", body).group(1)
        ur = re.search(r"unicode-range:\s*([^;]+);", body)
        blocks.append((fam, sty, wgt, url, ur.group(1).strip() if ur else ""))


parse(get(TEXT).decode("utf-8"), latin_only=True)
parse(get(SYM).decode("utf-8"), latin_only=False)

slug = lambda s: re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
faces, total = [], 0
for fam, sty, wgt, url, ur in blocks:
    name = f"{slug(fam)}-{wgt.replace(' ', '-')}.woff2"
    data = get(url)
    (OUT / name).write_bytes(data)
    total += len(data)
    face = (f"@font-face {{\n  font-family: '{fam}';\n  font-style: {sty};\n"
            f"  font-weight: {wgt};\n  font-display: swap;\n"
            f"  src: url('./fonts/{name}') format('woff2');")
    face += (f"\n  unicode-range: {ur};" if ur else "") + "\n}"
    faces.append(face)
    print(f"  {name:44} {len(data)//1024:5} KiB")

header = ("// Self-hosted web fonts. The gateway must run with NO internet, so the\n"
          "// console embeds every font instead of hitting Google Fonts. Files live\n"
          "// in src/styles/fonts/ (Angular bundles + hashes them). Regenerate with\n"
          "// console/tools/fetch-fonts.py; keep the CDN <link>s OUT of index.html.\n\n")
(CONSOLE / "src" / "styles" / "_fonts.scss").write_text(header + "\n\n".join(faces) + "\n")
print(f"\nTOTAL {total//1024} KiB across {len(faces)} faces -> src/styles/_fonts.scss")
