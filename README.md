# trust-anchor

Host trust anchors automatically, for any zone (including `.in` and second-level `.in` zones), formatted according to **RFC 9718** and **RFC 7958** (same standard as IANA `root-anchors.xml`).

## Overview

IANA hosts [root-anchors.xml](https://data.iana.org/root-anchors/root-anchors.xml) for use as trust anchors to verify DNSSEC in root servers.

**trust-anchor** consists of two components:
1. **`src/` (FastAPI Server)**: Generates and publishes RFC 9718 & RFC 7958 XML trust anchor files for `.in` and any sub-zone, including both KSK (`257`) and ZSK (`256`) keys and RRSIG `validFrom` timestamps.
2. **`fetch_trustanchors_bind.py` (BIND 9 Synchronizer)**: Dynamically discovers active signed zones from the `trust.aiori.in` status index, fetches the XML files, and keeps BIND 9 `trust-anchors { ... };` configuration up to date automatically.

## Features

- **RFC 9718 & RFC 7958 Compliance**: Includes `xmlns="urn:ietf:params:xml:ns:trust-anchor"`, `<KeyDigest id="..." validFrom="...">`, `<KeyTag>`, `<Algorithm>`, `<DigestType>`, `<Digest>`, `<PublicKey>`, and `<Flags>`.
- **Dynamic Zone Discovery**: `fetch_trustanchors_bind.py` automatically discovers new signed `.in` sub-zones directly from `https://trust.aiori.in/in-zone/` status index.
- **Default ZSK & KSK Coverage**: Automatically includes both **257 (KSK)** and **256 (ZSK)** keys.
- **Direct Authoritative Resolution**: Directly queries Root and TLD nameservers over UDP/TCP, bypassing local stub resolvers.

## Usage

### 1. Run the XML Publishing Server (`src/`)
```bash
uvicorn src.main:app --host 0.0.0.0 --port 8000
```
Published XML endpoints:
- `https://trust.aiori.in/in-zone/in.xml`
- `https://trust.aiori.in/in-zone/co-in.xml`
- `https://trust.aiori.in/in-zone/gov-in.xml`
- `https://trust.aiori.in/in-zone/` (HTML & JSON Status Index)

### 2. Synchronize BIND 9 Trust Anchors (`fetch_trustanchors_bind.py`)
```bash
python fetch_trustanchors_bind.py --conf /etc/bind/named.conf --apply rndc
```
Options:
- `--index-url`: Custom status index URL for dynamic discovery (default: `https://trust.aiori.in/in-zone/`)
- `--no-discover`: Disable dynamic discovery and use explicit sources
- `--no-zsk`: Exclude ZSKs (flags 256) and only include KSKs (flags 257)
- `--apply rndc`: Run `rndc reconfig` after updating `named.conf`


## License

See LICENSE file for details.

