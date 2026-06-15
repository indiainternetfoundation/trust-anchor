#!/usr/bin/env python3

import base64
import uuid
import xml.etree.ElementTree as ET

import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.dnssec

SOURCE = "generated"


def normalize_zone(zone):
    if zone == ".":
        return dns.name.root
    return dns.name.from_text(zone)

def get_dnskey_rrset(zone_name, resolver=None):
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

def get_ds_rrset(zone_name, resolver=None):
    """
    Fetch DS records from parent.
    For example:
      child = in.
      query parent "." for DS in.
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

def dnskey_to_base64(dnskey):
    """
    Convert DNSKEY RDATA to base64 public key.
    """
    return base64.b64encode(dnskey.key).decode()

def validate_dnskey_ds(dnskey_rrset, ds_rrset, zone_name):
    """
    Validate that at least one DNSKEY matches a DS record.

    Args:
        dnskey_rrset: DNSKEY RRset
        ds_rrset: DS RRset from parent
        zone_name: dns.name.Name object

    Returns:
        bool
    """

    for dnskey in dnskey_rrset:

        keytag = dns.dnssec.key_id(dnskey)

        for ds in ds_rrset:

            # Quick checks first
            if ds.key_tag != keytag:
                continue

            if ds.algorithm != dnskey.algorithm:
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

def build_xml(zone_text, dnskey_rrset, ds_rrset, source=SOURCE):
    """
    Build a TrustAnchor XML document.

    One <KeyDigest> is generated for each DS record.
    The matching DNSKEY (same key tag) is attached if found.
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

    # Build DNSKEY lookup by key tag
    dnskeys = {}

    for dnskey in dnskey_rrset:
        keytag = dns.dnssec.key_id(dnskey)
        dnskeys[keytag] = dnskey

    # One KeyDigest per DS record
    for idx, ds in enumerate(ds_rrset):

        kd = ET.SubElement(
            trust_anchor,
            "KeyDigest", { "id": f"K{str(ds.key_tag)}" }
        )

        ET.SubElement(kd, "KeyTag").text = str(ds.key_tag)
        ET.SubElement(kd, "Algorithm").text = str(ds.algorithm)
        ET.SubElement(kd, "DigestType").text = str(ds.digest_type)
        ET.SubElement(kd, "Digest").text = ds.digest.hex().upper()

        dnskey = dnskeys.get(ds.key_tag)

        if dnskey:
            ET.SubElement(kd, "PublicKey").text = (
                base64.b64encode(dnskey.key).decode()
            )

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


def generate_trust_anchor(zone):
    resolver = dns.resolver.Resolver()

    zone_name = normalize_zone(zone)

    dnskey_rrset = get_dnskey_rrset(zone_name, resolver)

    if zone_name == dns.name.root:
        raise ValueError(
            "Root zone requires obtaining DS digests from IANA trust-anchor data."
        )

    ds_rrset = get_ds_rrset(zone_name, resolver)

    if not validate_dnskey_ds(dnskey_rrset, ds_rrset, zone_name):
        raise ValueError("DNSKEY RRset does not match DS RRset")

    root = build_xml(
        zone_name.to_text(),
        dnskey_rrset,
        ds_rrset
    )

    pretty_indent(root)

    return ET.tostring(
        root,
        encoding="unicode"
    )

