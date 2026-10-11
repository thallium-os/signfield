"""Build a flattened, unsigned "display copy" of a verified PDF.

Legacy-layered signature appearances (Acrobat's /FRM with n0..n4) draw a
"?" in layer n1 and "Signature Not Verified" in n4; only Acrobat swaps
these live. Here we swap them for a green tick and "Signature valid",
paint the appearance into the page, and drop the signature field, since
any edit would break the signature anyway.
"""

import io
import re

from pyhanko.pdf_utils import generic as g
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer

# Display-copy tick in the 100x100 space of the n1 ("?") layer:
# tapered check with flat-cut tips, rgb(0,177,60), thin black outline and
# a black drop shadow offset down-right. Geometry matched to the reference display copy.
_CHECK = b"15.2 43 m 29.3 43 l 44.4 27.4 l 73 84.8 l 87 84.8 l 43.7 16.3 l h"
TICK = (b"q 0 g 1 0 0 1 3.5 -3.5 cm " + _CHECK + b" f Q\n"
        b"q 0 0.694 0.235 rg 0 G 0.9 w 1 j " + _CHECK + b" B Q\n")
SERIF = g.DictionaryObject({
    g.NameObject("/Type"): g.NameObject("/Font"),
    g.NameObject("/Subtype"): g.NameObject("/Type1"),
    g.NameObject("/BaseFont"): g.NameObject("/Times-Roman"),
    g.NameObject("/Encoding"): g.NameObject("/WinAnsiEncoding"),
})


def form_xobject(w, bbox, data: bytes, resources=None) -> g.IndirectObject:
    d = {
        g.NameObject("/Type"): g.NameObject("/XObject"),
        g.NameObject("/Subtype"): g.NameObject("/Form"),
        g.NameObject("/BBox"): g.ArrayObject(g.FloatObject(v) for v in bbox),
    }
    if resources is not None:
        d[g.NameObject("/Resources")] = resources
    return w.add_object(g.StreamObject(d, stream_data=data))


def swap_layers(w, ap_n: g.StreamObject, rect) -> bool:
    """Swap n1/n4 in a layered appearance. Returns False if it isn't layered."""
    try:
        frm = ap_n["/Resources"]["/XObject"]["/FRM"].get_object()
        layers = frm["/Resources"]["/XObject"]
    except KeyError:
        return False
    if "/n1" not in layers:
        return False
    layers[g.NameObject("/n1")] = form_xobject(w, [-10, -10, 110, 110], TICK)
    if "/n4" in layers:
        n4 = layers["/n4"].get_object()
        bbox = [float(v) for v in n4["/BBox"]]
        # Same start point and baseline as "Signature Not
        # Verified", in a serif at 1.43x its size, shrunk only to fit the box.
        # 6.083 em = "Signature valid" in Times-Roman.
        m = re.search(rb"([\d.]+) Tf", n4.data)
        tm = re.search(rb"1 0 0 1 ([\d.]+) ([\d.]+) Tm", n4.data)
        size = min((float(m[1]) if m else 6.0) * 1.43, (bbox[2] - bbox[0] - 2) / 6.083)
        x, y = (float(tm[1]), float(tm[2])) if tm else (bbox[0] + 2, bbox[1] + 0.25 * size)
        bbox[3] = max(bbox[3], y + size)  # don't clip the taller text
        text = b"BT /Serif %.2f Tf 0 g 1 0 0 1 %.2f %.2f Tm (Signature valid) Tj ET" % (size, x, y)
        res = g.DictionaryObject({g.NameObject("/Font"): g.DictionaryObject({g.NameObject("/Serif"): w.add_object(SERIF)})})
        layers[g.NameObject("/n4")] = form_xobject(w, bbox, text, res)
    return True


def make_display_copy(data: bytes, password: str, sha256: str) -> bytes:
    reader = PdfFileReader(io.BytesIO(data), strict=False)
    if reader.encrypted:
        reader.decrypt(password)
    w = copy_into_new_writer(reader)

    acroform = w.root["/AcroForm"]
    fields = acroform["/Fields"]
    sig_refs = [ref for ref in fields if ref.get_object().get("/FT") == "/Sig" and "/V" in ref.get_object()]
    page_count = int(w.root["/Pages"]["/Count"])
    page_refs = [w.find_page_for_modification(i)[0] for i in range(page_count)]

    wrapped: set[int] = set()
    for n, ref in enumerate(sig_refs):
        field = ref.get_object()
        rect = [float(v) for v in field["/Rect"]]
        page_ix = next(i for i, p in enumerate(page_refs) if p.idnum == field.raw_get("/P").idnum)
        page = page_refs[page_ix].get_object()

        # Flatten: draw the (patched) appearance where the widget sat, then
        # remove the widget and the field.
        if "/AP" in field and rect[2] > rect[0]:
            ap_ref = field["/AP"].raw_get("/N")
            ap_n = ap_ref.get_object()
            layered = swap_layers(w, ap_n, rect)
            bx0, by0, bx1, by1 = (float(v) for v in ap_n["/BBox"])
            sx, sy = (rect[2] - rect[0]) / (bx1 - bx0), (rect[3] - rect[1]) / (by1 - by0)
            ops = b"q %.4f 0 0 %.4f %.2f %.2f cm /SVsig%d Do Q\n" % (sx, sy, rect[0] - bx0 * sx, rect[1] - by0 * sy, n)
            if not layered:
                # Modern appearance with no status layer: put a tick at the left edge.
                size = min(24.0, rect[3] - rect[1])
                ops += b"q %.4f 0 0 %.4f %.2f %.2f cm " % (size / 100, size / 100, rect[0] + 2, (rect[1] + rect[3] - size) / 2) + TICK + b"Q\n"
            if page_ix not in wrapped:
                # Isolate the page's own content: some (e-Aadhaar) leave a
                # top-level cm in effect, which would warp our drawing.
                w.add_stream_to_page(page_ix, w.add_object(g.StreamObject(stream_data=b"q\n")), prepend=True)
                ops = b"Q\n" + ops
                wrapped.add(page_ix)
            res = g.DictionaryObject({g.NameObject("/XObject"): g.DictionaryObject({g.NameObject(f"/SVsig{n}"): ap_ref})})
            w.add_stream_to_page(page_ix, w.add_object(g.StreamObject(stream_data=ops)), resources=res)

        annots = page.get("/Annots")
        if annots is not None:
            page[g.NameObject("/Annots")] = g.ArrayObject(a for a in annots.get_object() if a.idnum != ref.idnum)

    acroform[g.NameObject("/Fields")] = g.ArrayObject(r for r in fields if r not in sig_refs)
    if "/SigFlags" in acroform:
        del acroform["/SigFlags"]
    if "/Perms" in w.root:
        del w.root["/Perms"]

    w.document_meta.subject = "Display copy - NOT digitally signed. The original signed PDF is the legal record."
    w.document_meta.keywords = [f"original-sha256:{sha256}"]
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()
