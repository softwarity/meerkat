#!/usr/bin/env python3
"""Vendor swagger-ui-dist into internal/admin/apidocs/dist/.

Meerkat is offline-first: the API-docs page must not load anything from a CDN,
so the two swagger-ui assets (JS bundle + CSS) are committed and embedded in
the binary via go:embed. Re-run this script to upgrade them:

    python3 tools/fetch-swagger-ui.py [version]

Without an argument it takes the latest release from the npm registry.
"""

import io
import json
import pathlib
import sys
import tarfile
import urllib.request

DEST = pathlib.Path(__file__).resolve().parent.parent / "internal/admin/apidocs/dist"
KEEP = {"swagger-ui-bundle.js", "swagger-ui.css", "LICENSE", "NOTICE"}


def main() -> None:
    version = sys.argv[1] if len(sys.argv) > 1 else None
    meta_url = f"https://registry.npmjs.org/swagger-ui-dist/{version or 'latest'}"
    with urllib.request.urlopen(meta_url) as r:
        meta = json.load(r)
    version, tarball = meta["version"], meta["dist"]["tarball"]
    print(f"swagger-ui-dist {version}")

    with urllib.request.urlopen(tarball) as r:
        data = r.read()
    DEST.mkdir(parents=True, exist_ok=True)
    kept = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = pathlib.PurePosixPath(member.name).name  # package/<file>
            if name in KEEP and member.isfile():
                extracted = tar.extractfile(member)
                assert extracted is not None
                (DEST / name).write_bytes(extracted.read())
                kept.append(name)
    (DEST / "VERSION").write_text(version + "\n")
    for name in sorted(kept):
        size = (DEST / name).stat().st_size
        print(f"  {name:24} {size / 1024:8.1f} KiB")


if __name__ == "__main__":
    main()
