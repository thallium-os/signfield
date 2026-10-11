# SignField

> A Thallium desktop app that validates digitally signed Indian government PDFs (e-Aadhaar, e-PAN, DigiLocker, GST, DSC-signed) and produces a verified display copy.

## What it does

- Checks every signature for:
  - **Integrity:** the signed bytes are unchanged.
  - **Coverage and later edits:** whether the signature covers the whole file, and any changes made after signing.
  - **Certificate chain:** a path to a CCA India root (2011, 2014, 2015 SPL, 2022, 2022 SPL).
  - **Validity at signing time:** judged on the document's own signing date.
  - **Revocation:** OCSP or CRL.
- Flags SHA-1 signatures as weak. Many government signers still produce them.
- **Verified copy:** for a valid file, builds a flattened PDF in which the signature box's "?" (the legacy `n1` layer) becomes a green tick, and "Signature Not Verified" (`n4`) becomes "Signature valid". The copy is *not* digitally signed. Its Keywords field holds the original's SHA-256.
- Previews the original and the verified copy side by side. Handles batches, password-protected PDFs, and CSV/JSON export.
- Files never leave the machine. The only network traffic is OCSP, CRL and AIA lookups to the certifying authorities.

## Quick Start

```sh
curl -fsSL https://signfield.thallium81.dev/install.sh | sh   # Debian 13, amd64
signfield
```

## Installation

- **CI:** `.github/workflows/build-deb.yml` builds the `.deb` in `debian:trixie` on every push.
- **Site + APT archive:** a `v*` tag runs `publish-site.yml`, which builds the `.deb`, signs a trixie archive (`scripts/build-site`) and deploys https://signfield.thallium81.dev as Worker static assets. Needs repo secrets `APT_SIGNING_KEY_B64` and `CLOUDFLARE_API_TOKEN`. Local deploy: `scripts/build-site _site dist && npx wrangler deploy`.
- **Local build:** `dpkg-buildpackage -us -uc -b`. It needs `debhelper`, `python3-pip` and network access, because the Python dependencies are vendored at build time.

Runtime dependencies: `python3` (3.13), `python3-pyqt6.qtwebengine`. pyHanko is vendored because it needs cryptography 48 or newer, and Debian 13 ships 43.

## Usage

- **Desktop:** launch **SignField** from the app menu. Drop, choose or paste PDFs, and click "Download verified copy". Downloads go to `~/Downloads`.
- **Development:** to run the web UI without Qt:

  ```sh
  uv sync
  uv run uvicorn --app-dir app server:app --port 8765
  ```

  Then open http://127.0.0.1:8765.
- **HTTP API:**
  - `POST /api/validate` (`file`, optional `password`) returns a JSON report.
  - `POST /api/display-copy` returns the verified copy, or 409 if the file isn't valid.
  - `POST /api/original` returns a decrypted copy for previewing.
  - `GET /api/roots` lists the trusted roots.

## Configuration

- **Trust roots:** the PEM files in `app/roots/`, from https://cca.gov.in/root_certificate.html.
- **Document-type labels:** the `DOC_TYPES` table in `app/server.py`, which matches on the signer's O and CN.

## Architecture

`signfield` (the launcher) starts the FastAPI app on a random free localhost port in a background thread, then opens it in a `QWebEngineView` with Chromium's PDF viewer enabled. `app/display.py` rewrites the layered signature appearance and flattens it into the page.

## License

GPL-3.0-or-later.
