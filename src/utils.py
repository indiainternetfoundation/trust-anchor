#!/usr/bin/env python3

import base64
import datetime
import uuid
import xml.etree.ElementTree as ET

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rcode

SOURCE = "generated"

# Root nameservers IPv4 addresses
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
    "192.5.5.241",     # f.root-servers.net
    "192.112.36.4",    # g.root-servers.net
    "128.63.2.53",     # h.root-servers.net
    "192.36.148.17",   # i.root-servers.net
    "192.58.128.30",   # j.root-servers.net
    "193.0.14.129",    # k.root-servers.net
    "199.7.83.42",     # l.root-servers.net
    "202.12.27.33",    # m.root-servers.net
]

# Fallback public recursive resolvers
PUBLIC_RESOLVERS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "1.0.0.1"
]


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
    """
    clean = slug.strip()
    if clean.endswith(".xml"):
        clean = clean[:-4]

    if clean in ("in-trust-anchor", "trust-anchor", "in"):
        return "in."

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
    """
    zone_clean = zone.strip().rstrip(".")
    if zone_clean == "in":
        return "in.xml"
    if zone_clean.endswith(".in"):
        prefix = zone_clean[:-3]
        hyphen_prefix = prefix.replace(".", "-")
        return f"{hyphen_prefix}-in.xml"
    return f"{zone_clean}.xml"


def direct_query(qname: dns.name.Name, rdtype: dns.rdatatype.RdataType, ns_ips: list[str], timeout=2.5) -> dns.message.Message | None:
    """
    Directly query authoritative nameservers via UDP (with TCP fallback if truncated),
    bypassing any local resolver.
    """
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    q.flags |= dns.flags.RD

    for ip in ns_ips:
        try:
            resp = dns.query.udp(q, ip, timeout=timeout)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(q, ip, timeout=timeout + 1.0)
            if resp.rcode() == dns.rcode.NOERROR and (resp.answer or resp.authority):
                return resp
        except Exception:
            pass

    # Fallback to public recursive resolvers if direct nameservers timed out
    for pub_ip in PUBLIC_RESOLVERS:
        try:
            resp = dns.query.udp(q, pub_ip, timeout=timeout)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(q, pub_ip, timeout=timeout + 1.0)
            if resp.rcode() == dns.rcode.NOERROR and (resp.answer or resp.authority):
                return resp
        except Exception:
            pass

    return None


def resolve_hostname_ips(hostnames: list[str]) -> list[str]:
    """
    Resolve nameserver hostnames to IP addresses directly.
    """
    ips = []
    for h in hostnames:
        h_name = dns.name.from_text(h) if isinstance(h, str) else h
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            q = dns.message.make_query(h_name, rdtype)
            q.flags |= dns.flags.RD
            for pub in PUBLIC_RESOLVERS:
                try:
                    resp = dns.query.udp(q, pub, timeout=2.0)
                    for rrset in resp.answer:
                        if rrset.rdtype == rdtype:
                            for item in rrset:
                                ips.append(item.address)
                    if ips:
                        break
                except Exception:
                    pass
    return ips


def get_ns_ips_for_zone(zone_name: dns.name.Name) -> list[str]:
    """
    Iteratively resolve authoritative nameserver IPs for a zone, starting from Root servers.
    """
    if zone_name == dns.name.root:
        return ROOT_SERVERS

    parent = zone_name.parent()
    parent_ns_ips = get_ns_ips_for_zone(parent)

    resp = direct_query(zone_name, dns.rdatatype.NS, parent_ns_ips)
    if not resp:
        return parent_ns_ips

    ns_ips = []
    for rrset in resp.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for rdata in rrset:
                ns_ips.append(rdata.address)

    if not ns_ips:
        hostnames = []
        for rrset in (resp.answer + resp.authority):
            if rrset.rdtype == dns.rdatatype.NS:
                for rdata in rrset:
                    hostnames.append(rdata.target.to_text())
        if hostnames:
            ns_ips = resolve_hostname_ips(hostnames)

    return ns_ips or parent_ns_ips


def get_ds_rrset(zone_name: dns.name.Name):
    """
    Fetch DS record directly from the parent zone's authoritative nameservers.
    """
    if zone_name == dns.name.root:
        raise ValueError("Root zone has no parent DS record")

    parent = zone_name.parent()
    parent_ns_ips = get_ns_ips_for_zone(parent)

    resp = direct_query(zone_name, dns.rdatatype.DS, parent_ns_ips)
    if not resp:
        return None

    for rrset in (resp.answer + resp.authority):
        if rrset.rdtype == dns.rdatatype.DS:
            return rrset

    return None


def get_dnskey_rrset_and_rrsig(zone_name: dns.name.Name):
    """
    Fetch DNSKEY RRset and RRSIG directly from the zone's authoritative nameservers.
    """
    zone_ns_ips = get_ns_ips_for_zone(zone_name)
    resp = direct_query(zone_name, dns.rdatatype.DNSKEY, zone_ns_ips)
    if not resp:
        return None, None

    dnskey_rrset = None
    rrsig_rrset = None

    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            dnskey_rrset = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            rrsig_rrset = rrset

    return dnskey_rrset, rrsig_rrset


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
    Build a TrustAnchor XML document matching RFC 7958 format.
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
    zone_name = normalize_zone(zone)

    if zone_name == dns.name.root:
        raise ValueError("Root zone requires obtaining DS digests from IANA trust-anchor data.")

    ds_rrset = get_ds_rrset(zone_name)
    if not ds_rrset:
        raise ValueError(f"No DS records found for zone '{zone_name.to_text()}' in parent zone")

    dnskey_rrset, rrsig_rrset = get_dnskey_rrset_and_rrsig(zone_name)
    if not dnskey_rrset:
        raise ValueError(f"No DNSKEY records found for zone '{zone_name.to_text()}'")

    if not validate_dnskey_ds(dnskey_rrset, ds_rrset, zone_name):
        raise ValueError(f"DNSKEY RRset does not validate against DS RRset for zone '{zone_name.to_text()}'")

    valid_from = None
    if rrsig_rrset:
        for sig in rrsig_rrset:
            dt = datetime.datetime.fromtimestamp(sig.inception, datetime.timezone.utc)
            valid_from = dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            break

    if not valid_from:
        valid_from = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    root = build_xml(
        zone_name.to_text(),
        dnskey_rrset,
        ds_rrset,
        source=source,
        valid_from=valid_from
    )

    pretty_indent(root)
    return ET.tostring(root, encoding="unicode")


