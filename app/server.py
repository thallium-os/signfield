"""SignField: validator for PDFs signed under the CCA India PKI."""

import hashlib
import io
from datetime import datetime, timezone
from pathlib import Path

from asn1crypto import x509
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from display import make_display_copy
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.crypt import AuthStatus
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko.sign.validation.utils import CMSAlgorithmUsagePolicy
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import AcceptAllAlgorithms

HERE = Path(__file__).parent
MAX_BYTES = 25 * 1024 * 1024
# Many Indian govt signers still use SHA-1; accept it and flag it as a note.
WEAK_HASHES = {"md5", "sha1"}
ALGO_POLICY = CMSAlgorithmUsagePolicy.lift_policy(AcceptAllAlgorithms())
ROOTS = [load_cert_from_pemder(str(p)) for p in sorted((HERE / "roots").glob("*.pem"))]

# Signer subject substring -> document type. Matched case-insensitively
# against the signer's O and CN.
DOC_TYPES = [
    ("UNIQUE IDENTIFICATION AUTHORITY", "e-Aadhaar (UIDAI)"),
    ("DIGILOCKER", "DigiLocker document"),
    ("INCOME TAX", "Income Tax Department (e-PAN / ITR)"),
    ("PROTEAN", "e-PAN (Protean)"),
    ("NSDL", "e-PAN (NSDL)"),
    ("UTIITSL", "e-PAN (UTIITSL)"),
    ("TRACES", "Form 16 / TRACES"),
    ("GOODS AND SERVICES TAX", "GST document"),
    ("GSTN", "GST document"),
    ("E-DISTRICT", "State e-District certificate"),
]

app = FastAPI(title="SignField")


def name_str(name: x509.Name) -> str:
    n = name.native
    return ", ".join(str(n[k]) for k in ("common_name", "organization_name") if k in n) or name.human_friendly


def guess_doc_type(cert: x509.Certificate) -> str:
    subject = cert.subject.native
    hay = " ".join(str(subject.get(k, "")) for k in ("organization_name", "common_name")).upper()
    return next((label for key, label in DOC_TYPES if key in hay), "Unrecognised (CCA-signed PDF)")


def cert_info(cert: x509.Certificate) -> dict:
    return {
        "subject": name_str(cert.subject),
        "issuer": name_str(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert["tbs_certificate"]["validity"]["not_before"].native.isoformat(),
        "not_after": cert["tbs_certificate"]["validity"]["not_after"].native.isoformat(),
        "is_root": cert.self_signed == "maybe" or cert.self_signed == "yes",
    }


def check(ok: bool | None, label: str, detail: str) -> dict:
    # ok=None means "note": not a failure, but not confirmed either.
    return {"status": "pass" if ok else ("note" if ok is None else "fail"), "label": label, "detail": detail}


async def validate_sig(sig: EmbeddedPdfSignature) -> dict:
    signed_at = sig.self_reported_timestamp
    # Validate at the document's own claimed signing time, so certificates
    # that have since expired are judged as they stood when the PDF was signed.
    vc = ValidationContext(
        trust_roots=ROOTS,
        allow_fetching=True,
        revocation_mode="soft-fail",
        moment=signed_at or datetime.now(timezone.utc),
        algorithm_usage_policy=AcceptAllAlgorithms(),
        # Today's OCSP/CRL postdates the signing time; accept it as evidence
        # that the certificate was not revoked back then.
        retroactive_revinfo=True,
    )
    try:
        st = await async_validate_pdf_signature(sig, signer_validation_context=vc, algorithm_policy=ALGO_POLICY)
    except (SignatureValidationError, ValueError) as e:
        # ValueError: the CMS blob itself is malformed (asn1crypto parse failure).
        return {"field": sig.field_name, "verdict": "invalid", "error": str(e), "checks": [], "chain": []}
    finally:
        await vc.aclose()

    cert = st.signing_cert
    chain = [cert_info(c) for c in st.validation_path.iter_certs(include_root=True)] if st.validation_path else [cert_info(cert)]
    chain.reverse()  # signer first, root last
    root = name_str(st.validation_path.trust_anchor.authority.name) if st.validation_path else None

    mod = st.modification_level
    full = st.coverage.name == "ENTIRE_FILE"
    revinfo = bool(vc.ocsps or vc.crls)

    checks = [
        check(st.intact and st.valid, "Integrity", "Signed bytes are unchanged and the cryptographic signature verifies."
              if st.intact and st.valid else "The signed content does not match the signature."),
        check(full or mod in (ModificationLevel.NONE, ModificationLevel.LTA_UPDATES),
              "Coverage", "Signature covers the whole file." if full else f"Signature covers {st.coverage.name.lower().replace('_', ' ')}."),
        check(None if mod is None else mod <= ModificationLevel.FORM_FILLING, "Later changes",
              "Could not analyse changes after signing." if mod is None
              else "No changes after signing." if mod == ModificationLevel.NONE
              else f"Changes after signing: {mod.name.lower().replace('_', ' ')}."),
        check(st.trusted, "Certificate chain", f"Chains to {root}." if st.trusted
              else f"Does not chain to a CCA India root ({st.trust_problem_indic})."),
        check(st.trusted, "Valid at signing time", f"Checked at {(signed_at or vc.moment).isoformat()} (document's own clock)."
              if st.trusted else "Could not establish validity at the signing time."),
        check(False if st.revoked else (True if revinfo else None), "Revocation",
              "Certificate was revoked." if st.revoked else ("Revocation status confirmed via OCSP/CRL." if revinfo
              else "Revocation could not be confirmed (authority did not respond).")),
    ]
    if st.md_algorithm in WEAK_HASHES:
        checks.append(check(None, "Hash algorithm", f"Signed with {st.md_algorithm.upper()}, which is considered weak today."))
    if st.timestamp_validity is not None:
        ts = st.timestamp_validity
        checks.append(check(ts.intact and ts.valid and ts.trusted, "Timestamp", f"Timestamp token at {ts.timestamp.isoformat()}."))

    hard_fail = any(c["status"] == "fail" for c in checks)
    return {
        "field": sig.field_name,
        "verdict": "invalid" if hard_fail else ("valid" if all(c["status"] == "pass" for c in checks[:5]) else "unknown"),
        "signer": name_str(cert.subject),
        "signed_at": signed_at.isoformat() if signed_at else None,
        "doc_type": guess_doc_type(cert),
        "checks": checks,
        "chain": chain,
    }


async def read_pdf(file: UploadFile) -> bytes:
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "File exceeds 25 MB.")
    if not data.startswith(b"%PDF"):
        raise HTTPException(400, "Not a PDF.")
    return data


async def run_validation(data: bytes, password: str, filename: str | None) -> dict:

    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        if reader.encrypted:
            if not password:
                raise HTTPException(401, "PDF is password-protected.")
            if reader.decrypt(password).status == AuthStatus.FAILED:
                raise HTTPException(401, "Wrong password.")
        sigs = [await validate_sig(s) for s in reader.embedded_regular_signatures]
    except (PdfError, ValueError) as e:
        # ValueError: an embedded signature blob is not valid CMS.
        raise HTTPException(422, f"PDF or its signature is damaged or unreadable: {e}")
    if not sigs:
        verdict = "unsigned"
    elif any(s["verdict"] == "invalid" for s in sigs):
        verdict = "invalid"
    elif all(s["verdict"] == "valid" for s in sigs):
        verdict = "valid"
    else:
        verdict = "unknown"
    return {
        "filename": filename,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "verdict": verdict,
        "signatures": sigs,
    }


@app.post("/api/validate")
async def validate(file: UploadFile = File(...), password: str = Form("")) -> dict:
    return await run_validation(await read_pdf(file), password, file.filename)


@app.post("/api/display-copy")
async def display_copy(file: UploadFile = File(...), password: str = Form("")) -> Response:
    data = await read_pdf(file)
    report = await run_validation(data, password, file.filename)
    if report["verdict"] != "valid":
        raise HTTPException(409, f"No display copy: verdict is {report['verdict']}.")
    try:
        pdf = make_display_copy(data, password, report["sha256"])
    except (PdfError, KeyError, StopIteration) as e:
        raise HTTPException(422, f"Could not build display copy: {e!r}")
    stem = Path(file.filename or "document.pdf").stem
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{stem}-verified.pdf"'})


@app.post("/api/original")
async def original(file: UploadFile = File(...), password: str = Form("")) -> Response:
    """Decrypted copy of an encrypted PDF, so the preview doesn't ask for the password again."""
    data = await read_pdf(file)
    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        if reader.encrypted and reader.decrypt(password).status == AuthStatus.FAILED:
            raise HTTPException(401, "Wrong password.")
        out = io.BytesIO()
        copy_into_new_writer(reader).write(out)
    except (PdfError, ValueError) as e:
        raise HTTPException(422, f"PDF is damaged or unreadable: {e}")
    return Response(out.getvalue(), media_type="application/pdf")


@app.get("/api/roots")
def roots() -> list[dict]:
    return [cert_info(c) for c in ROOTS]


@app.get("/")
def index() -> FileResponse:
    return FileResponse(HERE / "static" / "index.html")
