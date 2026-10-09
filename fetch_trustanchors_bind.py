#!/usr/bin/env python3
"""
Keep BIND static trust anchors in sync with
published trust-anchor XML (RFC 9718 / RFC 7958 format).

Sources
  .        https://data.iana.org/root-anchors/root-anchors.xml  (+ .p7s, verified with ICANN CA)
  in.*     Dynamically discovered from https://trust.aiori.in/in-zone/

What it does
  1. Dynamically discovers active signed .in zones from trust.aiori.in status index.
  2. Fetches each RFC 7958 / RFC 9718 XML, keeping only KeyDigest entries valid *now*
     (validFrom <= now < validUntil).
  3. Self-checks every entry: if <PublicKey>/<Flags> are present, it recomputes
     the key tag and the DS digest from the key and refuses the zone if they
     don't match <KeyTag>/<Digest>.
  4. Includes both KSKs (flags 257) and ZSKs (flags 256) by default.
  5. Rewrites the `trust-anchors { ... };` block in the given BIND config file.
  6. Backs up the file, runs named-checkconf, rolls back on failure.
  7. --apply rndc  -> rndc reconfig (+ optional flush).
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

# --------------------------------------------------------------------------- #
# Configuration — edit here or override with --source ZONE=URL
# --------------------------------------------------------------------------- #
IANA_XML = "https://data.iana.org/root-anchors/root-anchors.xml"
IANA_P7S = "https://data.iana.org/root-anchors/root-anchors.p7s"
IANA_CA = "https://data.iana.org/root-anchors/icannbundle.pem"
INDEX_URL = "https://trust.aiori.in/in-zone/"

SOURCES = {
    ".": IANA_XML,
    "in.": "https://trust.aiori.in/in-zone/in.xml",
    "co.in.": "https://trust.aiori.in/in-zone/co-in.xml",
    "gov.in.": "https://trust.aiori.in/in-zone/gov-in.xml",
    "ir.in.": "https://trust.aiori.in/in-zone/ir-in.xml",
    "ac.in.": "https://trust.aiori.in/in-zone/ac-in.xml",
    "res.in.": "https://trust.aiori.in/in-zone/res-in.xml",
    "nic.in.": "https://trust.aiori.in/in-zone/nic-in.xml",
}

DEFAULT_CONF = "/etc/bind/named.conf"
HTTP_TIMEOUT = 30
USER_AGENT = "aiori-trust-anchor-updater/2.0"


def log(msg):
    print(msg, file=sys.stderr)


def die(msg):
    log(f"ERROR: {msg}")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# DNSSEC helpers
# --------------------------------------------------------------------------- #
def norm_zone(z):
    z = z.strip().strip('"').lower()
    return z if z.endswith(".") else z + "."


def name_to_wire(zone):
    zone = norm_zone(zone)
    if zone == ".":
        return b"\x00"
    out = b""
    for label in zone[:-1].split("."):
        lb = label.encode("ascii")
        out += bytes([len(lb)]) + lb
    return out + b"\x00"


def dnskey_rdata(flags, alg, pubkey_b64):
    return struct.pack("!HBB", flags, 3, alg) + base64.b64decode(pubkey_b64)  # protocol is always 3


def key_tag(rdata):
    # RFC 4034 Appendix B
    acc = 0
    for i, b in enumerate(rdata):
        acc += b if i & 1 else b << 8
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


DIGESTS = {1: hashlib.sha1, 2: hashlib.sha256, 4: hashlib.sha384}


def ds_digest(zone, rdata, digest_type):
    if digest_type not in DIGESTS:
        raise ValueError(f"unsupported digest type {digest_type}")
    return DIGESTS[digest_type](name_to_wire(zone) + rdata).hexdigest().upper()


# --------------------------------------------------------------------------- #
# XML Namespace Helpers (RFC 7958 & RFC 9718 agnostic)
# --------------------------------------------------------------------------- #
def elem_tag(elem):
    return elem.tag.split("}", 1)[1] if "}" in elem.tag else elem.tag


def find_child(elem, name):
    for child in elem:
        if elem_tag(child) == name:
            return child
    return None


def find_children(elem, name):
    return [child for child in elem if elem_tag(child) == name]


# --------------------------------------------------------------------------- #
# Dynamic Index Discovery
# --------------------------------------------------------------------------- #
def discover_sources_from_index(index_url=INDEX_URL):
    """
    Dynamically discover signed & available .in zone trust anchor XML URLs from status index.
    """
    discovered = {}
    try:
        req = urllib.request.Request(
            index_url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            content = r.read().decode("utf-8")
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    z = item.get("zone")
                    u = item.get("url")
                    st = item.get("status", "")
                    if z and u and "Signed" in st:
                        discovered[norm_zone(z)] = u
    except Exception as e:
        log(f"  (Dynamic index lookup on {index_url} skipped: {e})")
    return discovered


# --------------------------------------------------------------------------- #
# Fetch + parse
# --------------------------------------------------------------------------- #
def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return r.read()


def read_source(src):
    """src may be an https:// URL or a local file path."""
    if re.match(r"^https?://", src):
        if not src.startswith("https://"):
            die(f"refusing non-HTTPS source {src}")
        return http_get(src)
    with open(src, "rb") as f:
        return f.read()


def verify_iana_signature(xml_bytes, ca_src):
    """Verify root-anchors.xml against its detached S/MIME signature (RFC 7958 s.4)."""
    if not shutil.which("openssl"):
        die("openssl not found; cannot verify IANA signature (use --no-verify-iana to skip)")
    with tempfile.TemporaryDirectory() as workdir:
        xml_p = os.path.join(workdir, "root-anchors.xml")
        sig_p = os.path.join(workdir, "root-anchors.p7s")
        with open(xml_p, "wb") as f:
            f.write(xml_bytes)
        with open(sig_p, "wb") as f:
            f.write(read_source(IANA_P7S))
        if os.path.exists(ca_src):
            ca_p = ca_src
        else:
            ca_p = os.path.join(workdir, "icannbundle.pem")
            with open(ca_p, "wb") as f:
                f.write(read_source(ca_src))
        last_err = ""
        for fmt in ("PEM", "DER"):
            cmd = ["openssl", "smime", "-verify", "-inform", fmt, "-in", sig_p,
                   "-content", xml_p, "-CAfile", ca_p, "-purpose", "any",
                   "-out", os.devnull]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                log("  IANA S/MIME signature: OK")
                return
            last_err = r.stderr.strip()
    die(f"IANA signature verification FAILED:\n{last_err}")


def parse_time(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    t = dt.datetime.fromisoformat(s)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def parse_anchor_xml(xml_bytes, expected_zone, now, include_zsk=True):
    """Return list of anchor dicts that are currently valid and self-consistent (RFC 7958 & RFC 9718)."""
    root = ET.fromstring(xml_bytes)
    if elem_tag(root) != "TrustAnchor":
        raise ValueError(f"root element is <{root.tag}>, expected <TrustAnchor>")
    zone_el = find_child(root, "Zone")
    if zone_el is None or not zone_el.text:
        raise ValueError("missing <Zone>")
    zone = norm_zone(zone_el.text)
    if zone != norm_zone(expected_zone):
        raise ValueError(f"XML is for zone '{zone}', expected '{norm_zone(expected_zone)}'")

    anchors = []
    for kd in find_children(root, "KeyDigest"):
        kid = kd.get("id", "?")
        vf, vu = parse_time(kd.get("validFrom")), parse_time(kd.get("validUntil"))
        if vf and now < vf:
            log(f"  skip {kid}: not valid until {vf.isoformat()}")
            continue
        if vu and now >= vu:
            log(f"  skip {kid}: expired {vu.isoformat()}")
            continue

        def txt(tag, required=True):
            el = find_child(kd, tag)
            if el is None or el.text is None or not el.text.strip():
                if required:
                    raise ValueError(f"{kid}: missing <{tag}>")
                return None
            return el.text.strip()

        a = {
            "zone": zone,
            "id": kid,
            "keytag": int(txt("KeyTag")),
            "alg": int(txt("Algorithm")),
            "dtype": int(txt("DigestType")),
            "digest": re.sub(r"\s+", "", txt("Digest")).upper(),
            "pubkey": None,
            "flags": None,
        }
        pk, fl = txt("PublicKey", False), txt("Flags", False)
        if pk is not None:
            a["pubkey"] = re.sub(r"\s+", "", pk)
            a["flags"] = int(fl) if fl is not None else 257

        if a["pubkey"]:
            rd = dnskey_rdata(a["flags"], a["alg"], a["pubkey"])
            kt = key_tag(rd)
            if kt != a["keytag"]:
                raise ValueError(f"{kid}: key tag mismatch: XML says {a['keytag']}, key computes {kt}")
            if a["flags"] & 0x0001:  # SEP bit -> DS digest must match
                calc = ds_digest(zone, rd, a["dtype"])
                if calc != a["digest"]:
                    raise ValueError(f"{kid}: DS digest mismatch:\n    XML  {a['digest']}\n    calc {calc}")
            if a["flags"] & 0x0080:
                log(f"  skip {kid}: REVOKE bit set")
                continue
            if not (a["flags"] & 0x0001):
                if not include_zsk:
                    log(f"  skip {kid}: ZSK (flags {a['flags']}); ZSK inclusion is disabled")
                    continue
        anchors.append(a)
        log(f"  ok   {kid}: keytag {a['keytag']} alg {a['alg']}"
            + (f" flags {a['flags']}" if a['flags'] else " (DS only)"))
    if not anchors:
        raise ValueError("no currently-valid anchors in XML")
    return anchors


def crosscheck_parent_ds(anchors, resolver):
    """Compare XML DS with DS published in the parent zone (via dig)."""
    if not shutil.which("dig"):
        log("  crosscheck: dig not found, skipped")
        return True
    zone = anchors[0]["zone"]
    if zone == ".":
        return True  # root has no parent; IANA signature covers it
    cmd = ["dig", "+short", "+time=5", "+tries=2", "DS", zone]
    if resolver:
        cmd.insert(1, f"@{resolver}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    live = set()
    for line in r.stdout.splitlines():
        p = line.split()
        if len(p) >= 4 and p[0].isdigit():
            live.add((int(p[0]), int(p[1]), int(p[2]), "".join(p[3:]).upper()))
    if not live:
        log(f"  crosscheck {zone}: parent returned no DS (unsigned delegation or lookup failed)")
        return False
    ok = True
    for a in anchors:
        if a["pubkey"] and not (a["flags"] & 1):
            continue
        t = (a["keytag"], a["alg"], a["dtype"], a["digest"])
        if t in live:
            log(f"  crosscheck {zone} keytag {a['keytag']}: matches parent DS")
        else:
            log(f"  crosscheck {zone} keytag {a['keytag']}: NOT in parent DS set {sorted(live)}")
            ok = False
    return ok


# --------------------------------------------------------------------------- #
# BIND config rendering
# --------------------------------------------------------------------------- #
def render_entries(anchors, mode):
    """mode: ds | key | both. Falls back to DS when the XML has no PublicKey."""
    lines = []
    for a in anchors:
        q = f'"{a["zone"]}"'
        is_ksk = a["pubkey"] is None or (a["flags"] & 1)
        if is_ksk and (mode in ("ds", "both") or not a["pubkey"]):
            lines.append(f'{q} static-ds {a["keytag"]} {a["alg"]} {a["dtype"]} "{a["digest"]}";')
        if a["pubkey"] and (mode in ("key", "both") or not is_ksk):
            lines.append(f'{q} static-key {a["flags"]} 3 {a["alg"]} "{a["pubkey"]}";')
    return lines


def entry_key(stmt):
    """Normalise one trust-anchors statement for comparison. Returns (zone, tuple) or None."""
    toks = re.findall(r'"[^"]*"|[^\s;]+', stmt)
    if len(toks) < 2:
        return None
    zone = norm_zone(toks[0])
    kind = toks[1].lower()
    rest = []
    for t in toks[2:]:
        rest.append(re.sub(r"\s+", "", t.strip('"')))
    if kind.endswith("-ds") and rest:
        rest[-1] = rest[-1].upper()
    return zone, (kind, *rest)


# --------------------------------------------------------------------------- #
# Minimal named.conf scanner (comments + strings aware)
# --------------------------------------------------------------------------- #
def scan(text):
    """Yield (index, char) for chars outside comments and strings, plus string spans as one token."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            yield i, text[i:j + 1]
            i = j + 1
        elif text.startswith("//", i) or c == "#":
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            yield i, c
            i += 1


def find_blocks(text, keyword):
    """Return list of (start, open_brace, close_brace, end) for top-level `keyword { ... };`."""
    blocks, depth, word_start, buf = [], 0, None, ""
    pending = None
    toks = list(scan(text))
    k = 0
    while k < len(toks):
        i, c = toks[k]
        if len(c) == 1 and (c.isalnum() or c in "-_"):
            if not buf:
                word_start = i
            buf += c
        else:
            if buf:
                if depth == 0 and buf == keyword:
                    pending = word_start
                buf = ""
            if c == "{":
                if depth == 0 and pending is not None:
                    open_i, d = i, 1
                    k += 1
                    while k < len(toks) and d:
                        j, cc = toks[k]
                        if cc == "{":
                            d += 1
                        elif cc == "}":
                            d -= 1
                            if d == 0:
                                close_i = j
                                break
                        k += 1
                    if d:
                        raise ValueError(f"unbalanced braces in {keyword} block")
                    k += 1
                    while k < len(toks) and toks[k][1].isspace():
                        k += 1
                    if k >= len(toks) or toks[k][1] != ";":
                        raise ValueError(f"missing ';' after {keyword} block")
                    blocks.append((pending, open_i, close_i, toks[k][0] + 1))
                    pending = None
                else:
                    depth += 1
            elif c == "}":
                depth -= 1
            elif c == ";" and depth == 0:
                pending = None
        k += 1
    return blocks


def split_statements(body):
    """Split a block body into [(leading_text_incl_comments, statement_text)], keeping trailing text."""
    out, last = [], 0
    for i, c in scan(body):
        if c == ";":
            chunk = body[last:i + 1]
            m_stmt = None
            for j, cc in scan(chunk):
                if not cc.isspace():
                    m_stmt = j
                    break
            lead = chunk[:m_stmt] if m_stmt is not None else chunk
            stmt = chunk[m_stmt:] if m_stmt is not None else ""
            out.append((lead, stmt))
            last = i + 1
    return out, body[last:]


def update_config_text(text, new_by_zone):
    """Return (new_text, changed: bool, summary lines)."""
    managed = set(new_by_zone)
    blocks = find_blocks(text, "trust-anchors")
    if len(blocks) > 1:
        raise ValueError("more than one top-level trust-anchors block; merge them first")

    for legacy in ("trusted-keys", "managed-keys"):
        if find_blocks(text, legacy):
            log(f"WARNING: config contains a legacy '{legacy}' block; BIND refuses mixing it "
                f"with trust-anchors for the same name. Migrate it to trust-anchors.")

    desired = {z: {entry_key(l)[1] for l in lines} for z, lines in new_by_zone.items()}
    summary = []

    if not blocks:
        text += ("" if not text or text.endswith("\n") else "\n") + "\ntrust-anchors {\n};\n"
        blocks = find_blocks(text, "trust-anchors")

    start, ob, cb, end = blocks[0]
    body = text[ob + 1:cb]
    stmts, tail = split_statements(body)

    existing = {}
    kept = []
    for lead, stmt in stmts:
        ek = entry_key(stmt)
        if ek and ek[0] in managed:
            existing.setdefault(ek[0], set()).add(ek[1])
            continue
        kept.append(lead + stmt)

    changed = False
    for z in new_by_zone:
        old = existing.get(z, set())
        if old == desired[z]:
            summary.append(f"  {z}: unchanged")
        else:
            changed = True
            added, removed = desired[z] - old, old - desired[z]
            summary.append(f"  {z}: " + ("added" if not old else
                           f"updated (+{len(added)} / -{len(removed)})"))
    if not changed:
        return text, False, summary

    parts = [k.rstrip() for k in kept if k.strip()]
    new_body = "\n".join(parts)
    if new_body:
        new_body += "\n"
    for z, lines in new_by_zone.items():
        new_body += f"\n    // {z} — managed by fetch_trustanchors_bind.py\n"
        new_body += "\n".join(f"    {l}" for l in lines) + "\n"
    new_text = text[:ob + 1] + new_body + (tail if tail.strip() else "") + text[cb:]
    return new_text, True, summary


# --------------------------------------------------------------------------- #
# Apply
# --------------------------------------------------------------------------- #
def run(cmd):
    log(f"$ {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout.strip():
        log(r.stdout.rstrip())
    if r.stderr.strip():
        log(r.stderr.rstrip())
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--conf", default=DEFAULT_CONF,
                    help="file holding (or to receive) the trust-anchors block (default %(default)s)")
    ap.add_argument("--main-conf", default=None,
                    help="top-level named.conf for named-checkconf (default: same as --conf)")
    ap.add_argument("--source", action="append", default=[], metavar="ZONE=URL|PATH",
                    help="override/add a source, e.g. --source gov.in.=https://... (repeatable)")
    ap.add_argument("--index-url", default=INDEX_URL,
                    help="status index URL to dynamically discover signed zones (default %(default)s)")
    ap.add_argument("--no-discover", action="store_true",
                    help="disable dynamic zone discovery from --index-url")
    ap.add_argument("--zones", default=None,
                    help="comma list of zones to manage (default: all discovered/configured)")
    ap.add_argument("--mode", choices=("ds", "key", "both"), default="both",
                    help="emit static-ds, static-key, or both (default both)")
    ap.add_argument("--include-zsk", action="store_true", dest="include_zsk", default=True,
                    help="include ZSKs (flags 256) in addition to KSKs (default: True)")
    ap.add_argument("--no-zsk", action="store_false", dest="include_zsk",
                    help="exclude ZSKs (flags 256) and only pin KSKs (flags 257)")
    ap.add_argument("--no-verify-iana", action="store_true",
                    help="skip S/MIME verification of root-anchors.xml")
    ap.add_argument("--icann-ca", default=IANA_CA,
                    help="ICANN CA bundle")
    ap.add_argument("--crosscheck", action="store_true",
                    help="compare non-root DS with parent zone (needs dig)")
    ap.add_argument("--crosscheck-resolver", default=None, help="resolver IP for --crosscheck")
    ap.add_argument("--strict", action="store_true",
                    help="abort the whole run if any zone fails")
    ap.add_argument("--apply", choices=("none", "rndc"), default="none",
                    help="after writing: 'rndc' runs rndc reconfig")
    ap.add_argument("--flush", action="store_true", help="rndc flush after reconfig")
    ap.add_argument("--dry-run", action="store_true", help="print the new config, write nothing")
    args = ap.parse_args()

    # 1. Base sources (Root zone)
    sources = {".": IANA_XML}

    # 2. Dynamically discover signed .in zones from trust.aiori.in index
    if not args.no_discover and args.index_url:
        discovered = discover_sources_from_index(args.index_url)
        if discovered:
            log(f"Dynamically discovered {len(discovered)} signed zone(s) from {args.index_url}")
            sources.update(discovered)

    # 3. Fallback default sources if discovery not available
    if len(sources) <= 1:
        sources.update({norm_zone(z): u for z, u in SOURCES.items()})

    # 4. Command line source overrides
    for s in args.source:
        if "=" not in s:
            die(f"bad --source '{s}', expected ZONE=URL")
        z, u = s.split("=", 1)
        sources[norm_zone(z)] = u

    if args.zones:
        wanted = [norm_zone(z) for z in args.zones.split(",")]
        sources = {z: sources.get(z) for z in wanted}

    now = dt.datetime.now(dt.timezone.utc)
    new_by_zone, failures = {}, []
    for zone, src in sources.items():
        log(f"[{zone}] {src or '(no source configured)'}")
        if not src:
            log("  skipped: no source URL — existing anchors left as they are")
            continue
        try:
            xml_bytes = read_source(src)
            if zone == "." and not args.no_verify_iana:
                verify_iana_signature(xml_bytes, args.icann_ca)
            anchors = parse_anchor_xml(xml_bytes, zone, now, include_zsk=args.include_zsk)
            if args.crosscheck and not crosscheck_parent_ds(anchors, args.crosscheck_resolver):
                raise ValueError("parent DS crosscheck failed")
            new_by_zone[zone] = render_entries(anchors, args.mode)
        except Exception as e:
            log(f"  FAILED: {e}")
            failures.append(zone)
            if args.strict:
                die(f"{zone} failed and --strict is set; nothing written")

    if not new_by_zone:
        die("no zones fetched successfully; nothing to do")

    try:
        with open(args.conf, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        log(f"{args.conf} does not exist; it will be created")
        text = ""

    new_text, changed, summary = update_config_text(text, new_by_zone)
    log("\nSummary:")
    for s in summary:
        log(s)
    if failures:
        log(f"  failed (left untouched): {', '.join(failures)}")

    if not changed:
        log("Trust anchors already up to date — nothing written.")
        return 2 if failures else 0

    if args.dry_run:
        print("\n" + new_text)
        return 0

    main_conf = args.main_conf or args.conf
    backup = None
    if os.path.exists(args.conf):
        backup = f"{args.conf}.bak-{now.strftime('%Y%m%dT%H%M%SZ')}"
        shutil.copy2(args.conf, backup)
        log(f"Backup: {backup}")
    d = os.path.dirname(os.path.abspath(args.conf))
    fd, tmp = tempfile.mkstemp(prefix=".ta-", dir=d)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new_text)
    if backup:
        shutil.copymode(backup, tmp)
        try:
            st = os.stat(backup)
            os.chown(tmp, st.st_uid, st.st_gid)
        except (PermissionError, AttributeError):
            pass
    os.replace(tmp, args.conf)
    log(f"Wrote {args.conf}")

    if not shutil.which("named-checkconf"):
        log("WARNING: named-checkconf not found; config NOT validated")
    elif run(["named-checkconf", main_conf]) != 0:
        if backup:
            shutil.copy2(backup, args.conf)
            die("named-checkconf failed — original config restored")
        die("named-checkconf failed")

    if args.apply == "rndc":
        if run(["rndc", "reconfig"]) != 0:
            die("rndc failed — config is written but named did not load it")
        if args.flush:
            run(["rndc", "flush"])
        run(["rndc", "secroots", "-"])
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
