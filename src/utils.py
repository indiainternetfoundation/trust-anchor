#!/usr/bin/env python3

import base64
import datetime
import uuid
import xml.etree.ElementTree as ET

import dns.dnssec
import dns.flags
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

SOURCE = "generated"


def normalize_zone(zone: str) -> dns.name.Name:
    zone_str = zone.strip()
    if not zone_str.endswith("."):
        zone_str += "."
    if zone_str == ".":
        return dns.name.root
    return dns.name.from_text(zone_str)


def slug_to_zone(slug: str) -> str:
    """
    Convert URL slug or filename to canonical zone name.
    Examples:
        'in.xml' or 'in' -> 'in.'
        'co-in.xml' or 'co-in' -> 'co.in.'
        'gov-in.xml' or 'gov-in' -> 'gov.in.'
        'co.in.xml' or 'co.in' -> 'co.in.'
        'trust-anchor.xml' -> 'in.' (or default)
    """
    clean = slug.strip()
    if clean.endswith(".xml"):
        clean = clean[:-4]

    if clean in ("in-trust-anchor", "trust-anchor", "in"):
        return "in."

    # Handle dash separated subzones under .in (e.g. co-in -> co.in.)
    if clean.endswith("-in"):
        prefix = clean[:-3]
        dots_prefix = prefix.replace("-", ".")
        return f"{dots_prefix}.in."

    if not clean.endswith("."):
        clean += "."

    return clean


def zone_to_slug(zone: str) -> str:
    """
    Convert canonical zone name to URL filename slug.
    Examples:
        'in.' -> 'in.xml'
        'co.in.' -> 'co-in.xml'
        'gov.in.' -> 'gov-in.xml'
    """
    zone_clean = zone.strip().rstrip(".")
    if zone_clean == "in":
        return "in.xml"
    if zone_clean.endswith(".in"):
        prefix = zone_clean[:-3]
        hyphen_prefix = prefix.replace(".", "-")
        return f"{hyphen_prefix}-in.xml"
    return f"{zone_clean}.xml"


def get_dnskey_rrset(zone_name: dns.name.Name, resolver=None):
    """
    Fetch DNSKEY RRset via recursive resolver.
    """
    resolver = resolver or dns.resolver.Resolver()
    answer = resolver.resolve(
        zone_name.to_text(),
        dns.rdatatype.DNSKEY,
        raise_on_no_answer=False
    )
    return answer.rrset


def get_ds_rrset(zone_name: dns.name.Name, resolver=None):
    """
    Fetch DS records from parent zone.
    """
    resolver = resolver or dns.resolver.Resolver()
    if zone_name == dns.name.root:
        raise ValueError("Root zone has no parent DS record")

    answer = resolver.resolve(
        zone_name.to_text(),
        dns.rdatatype.DS,
        raise_on_no_answer=False
    )
    return answer.rrset


def get_rrsig_inception(zone_name: dns.name.Name, resolver=None) -> str:
    """
    Attempt to fetch the RRSIG inception time for the zone DNSKEY set.
    Returns ISO 8601 formatted timestamp string in UTC.
    """
    resolver = resolver or dns.resolver.Resolver()
    try:
        resolver.use_edns(0, ednsflags=dns.flags.DO, payload=4096)
        answer = resolver.resolve(zone_name.to_text(), dns.rdatatype.DNSKEY)
        for rrset in answer.response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                for sig in rrset:
                    dt = datetime.datetime.fromtimestamp(sig.inception, datetime.timezone.utc)
                    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    except Exception:
        pass
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def dnskey_to_base64(dnskey) -> str:
    """
    Convert DNSKEY RDATA to base64 public key.
    """
    return base64.b64encode(dnskey.key).decode()


def validate_dnskey_ds(dnskey_rrset, ds_rrset, zone_name: dns.name.Name) -> bool:
    """
    Validate that at least one DNSKEY matches a DS record.
    """
    if not dnskey_rrset or not ds_rrset:
        return False

    for dnskey in dnskey_rrset:
        keytag = dns.dnssec.key_id(dnskey)
        for ds in ds_rrset:
            if ds.key_tag != keytag or ds.algorithm != dnskey.algorithm:
                continue

            try:
                computed_ds = dns.dnssec.make_ds(
                    zone_name,
                    dnskey,
                    ds.digest_type
                )
            except Exception:
                continue

            if (
                computed_ds.key_tag == ds.key_tag and
                computed_ds.algorithm == ds.algorithm and
                computed_ds.digest_type == ds.digest_type and
                computed_ds.digest == ds.digest
            ):
                return True

    return False


def build_xml(zone_text: str, dnskey_rrset, ds_rrset, source=SOURCE, valid_from=None) -> ET.Element:
    """
    Build a TrustAnchor XML document matching RFC 7958 format (same as root-anchors.xml).

    One <KeyDigest> is generated for each DS record.
    Matching DNSKEY (same key tag) attaches <PublicKey> and <Flags>.
    """
    trust_anchor = ET.Element(
        "TrustAnchor",
        {
            "id": str(uuid.uuid4()).upper(),
            "source": source
        }
    )

    zone_elem = ET.SubElement(trust_anchor, "Zone")
    zone_elem.text = zone_text

    dnskeys = {}
    if dnskey_rrset:
        for dnskey in dnskey_rrset:
            keytag = dns.dnssec.key_id(dnskey)
            dnskeys[keytag] = dnskey

    if not valid_from:
        valid_from = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    for ds in (ds_rrset or []):
        kd_attrs = {"id": f"K{ds.key_tag}"}
        if valid_from:
            kd_attrs["validFrom"] = valid_from

        kd = ET.SubElement(trust_anchor, "KeyDigest", kd_attrs)

        ET.SubElement(kd, "KeyTag").text = str(ds.key_tag)
        ET.SubElement(kd, "Algorithm").text = str(ds.algorithm)
        ET.SubElement(kd, "DigestType").text = str(ds.digest_type)
        ET.SubElement(kd, "Digest").text = ds.digest.hex().upper()

        dnskey = dnskeys.get(ds.key_tag)
        if dnskey:
            ET.SubElement(kd, "PublicKey").text = base64.b64encode(dnskey.key).decode()
            ET.SubElement(kd, "Flags").text = str(dnskey.flags)

    return trust_anchor


def pretty_indent(elem, level=0):
    i = "\n" + level * "    "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "    "
        for child in elem:
            pretty_indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i


def generate_trust_anchor(zone: str, source=SOURCE) -> str:
    resolver = dns.resolver.Resolver()
    zone_name = normalize_zone(zone)

    if zone_name == dns.name.root:
        raise ValueError("Root zone requires obtaining DS digests from IANA trust-anchor data.")

    dnskey_rrset = get_dnskey_rrset(zone_name, resolver)
    if not dnskey_rrset:
        raise ValueError(f"No DNSKEY records found for zone '{zone_name.to_text()}'")

    ds_rrset = get_ds_rrset(zone_name, resolver)
    if not ds_rrset:
        raise ValueError(f"No DS records found for zone '{zone_name.to_text()}' in parent zone")

    if not validate_dnskey_ds(dnskey_rrset, ds_rrset, zone_name):
        raise ValueError(f"DNSKEY RRset does not validate against DS RRset for zone '{zone_name.to_text()}'")

    valid_from = get_rrsig_inception(zone_name, resolver)

    root = build_xml(
        zone_name.to_text(),
        dnskey_rrset,
        ds_rrset,
        source=source,
        valid_from=valid_from
    )

    pretty_indent(root)
    return ET.tostring(root, encoding="unicode")


