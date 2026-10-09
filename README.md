# trust-anchor

Host trust anchors automatically, for any zone (including `.in` and second-level `.in` zones), formatted according to RFC 7958 (same standard as IANA `root-anchors.xml`).

## Overview

IANA hosts [root-anchors.xml](https://data.iana.org/root-anchors/root-anchors.xml) for use as trust anchors to verify DNSSEC in root servers. However, no trust anchor is maintained for other zones (TLDs, SLDs, or sub-zones), even though this is compliant with existing RFCs.

**trust-anchor** is a FastAPI-based server that:
- Fetches DNSSEC trust anchors (DNSKEY and DS records) for `.in` and any requested zone
- Extracts signature inception metadata (`validFrom`) from DNSSEC RRSIGs
- Validates the DNSKEY and DS record relationships cryptographically
- Publishes trust anchors in RFC 7958 XML format (identical to IANA root trust anchor structure)
- Supports multi-zone endpoints under `/in-zone/{zone-slug}.xml` (e.g. `in.xml`, `co-in.xml`, `gov-in.xml`, `ac-in.xml`)
- Automatically refreshes trust anchors at configurable background intervals

## Features

- 🔄 **Multi-Zone & Sub-Zone Support**: Serves `in.`, `co.in.`, `gov.in.`, `ac.in.`, `res.in.`, `nic.in.`, `firm.in.`, `net.in.`, `org.in.`, `gen.in.`, `ind.in.`, `edu.in.`, `mil.in.`, `bank.in.`, `fin.in.`, etc.
- 📜 **RFC 7958 Format**: Includes `<KeyDigest id="..." validFrom="...">`, `<KeyTag>`, `<Algorithm>`, `<DigestType>`, `<Digest>`, `<PublicKey>`, and `<Flags>`.
- 🛡️ **DNSSEC Validation**: Validates child DNSKEY records against parent DS records.
- 🔗 **Flexible URL Routing**: Serves `/in-zone/in.xml`, `/in-zone/co-in.xml`, `/in-zone/gov-in.xml`, etc.
- ⚡ **Caching & On-Demand Fetching**: Pre-caches active signed zones and dynamically resolves any requested zone on demand.

## Endpoint Structure

| URL Pattern | Zone Name | Description |
| :--- | :--- | :--- |
| `https://trust.aiori.in/in-zone/in.xml` | `in.` | Main `.in` TLD trust anchor |
| `https://trust.aiori.in/in-zone/co-in.xml` | `co.in.` | Commercial sub-zone trust anchor |
| `https://trust.aiori.in/in-zone/gov-in.xml` | `gov.in.` | Government sub-zone trust anchor |
| `https://trust.aiori.in/in-zone/ac-in.xml` | `ac.in.` | Academic sub-zone trust anchor |
| `https://trust.aiori.in/in-zone/` | All | Directory & Status index of all `.in` zones |

## Installation & Running

1. Clone and install dependencies:
```bash
git clone https://github.com/indiainternetfoundation/trust-anchor
cd trust-anchor
pip install -r requirements.txt
```

2. Configure environment variables in `.env`:
```env
ZONE=in.
SOURCE=https://trust.aiori.in/in-zone/in.xml
ENDPOINT=trust-anchor.xml
REFRESH_INTERVAL=3600
```

3. Run the server:
```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

## License

See LICENSE file for details.

