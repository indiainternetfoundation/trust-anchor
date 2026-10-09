#!/usr/bin/env python3

import asyncio
from contextlib import asynccontextmanager
import logging
import os
import time

from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse
from dotenv import load_dotenv

from .utils import (
    generate_trust_anchor,
    slug_to_zone,
    zone_to_slug,
    normalize_zone
)

# Load environment variables
load_dotenv()

ENDPOINT = os.getenv("ENDPOINT", "trust-anchor.xml")
SOURCE = os.getenv("SOURCE", "https://trust.aiori.in/in-zone/in-trust-anchor.xml")
PRIMARY_ZONE = os.getenv("ZONE", "in.")
REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", "3600"))

# Known signed .in zones
KNOWN_SIGNED_ZONES = [
    "in.",
    "co.in.",
    "firm.in.",
    "net.in.",
    "org.in.",
    "gen.in.",
    "ind.in.",
    "ac.in.",
    "edu.in.",
    "res.in.",
    "gov.in.",
    "mil.in.",
    "bank.in.",
    "fin.in.",
    "nic.in."
]

# All requested .in zones list for reference
ALL_IN_ZONES = [
    "in.", "co.in.", "com.in.", "firm.in.", "net.in.", "org.in.", "gen.in.", "ind.in.",
    "ernet.in.", "ac.in.", "edu.in.", "res.in.", "gov.in.", "mil.in.", "bank.in.", "fin.in.", "nic.in.",
    "5g.in.", "6g.in.", "ai.in.", "am.in.", "bihar.in.", "biz.in.", "business.in.", "ca.in.", "cn.in.",
    "coop.in.", "cs.in.", "delhi.in.", "dr.in.", "er.in.", "gujarat.in.", "info.in.", "int.in.",
    "internet.in.", "io.in.", "me.in.", "pg.in.", "post.in.", "pro.in.", "travel.in.", "tv.in.",
    "uk.in.", "up.in.", "us.in."
]

# Cache dict: {zone_name: {"xml": str, "last_refresh": float, "last_error": str}}
ZONE_CACHE = {}


def fetch_and_cache_zone(zone: str) -> str:
    zone_norm = normalize_zone(zone).to_text()
    source_url = f"https://trust.aiori.in/in-zone/{zone_to_slug(zone_norm)}"
    try:
        xml_str = generate_trust_anchor(zone_norm, source=source_url)
        ZONE_CACHE[zone_norm] = {
            "xml": xml_str,
            "last_refresh": time.time(),
            "last_error": None
        }
        return xml_str
    except Exception as e:
        ZONE_CACHE[zone_norm] = {
            "xml": ZONE_CACHE.get(zone_norm, {}).get("xml"),
            "last_refresh": ZONE_CACHE.get(zone_norm, {}).get("last_refresh"),
            "last_error": str(e)
        }
        raise e


async def refresh_all_zones():
    """Periodic background worker to refresh trust anchors for configured & active zones."""
    while True:
        target_zones = set(KNOWN_SIGNED_ZONES + [PRIMARY_ZONE] + list(ZONE_CACHE.keys()))
        for zone in target_zones:
            try:
                fetch_and_cache_zone(zone)
                logging.info(f"Refreshed trust anchor for zone {zone}")
            except Exception as e:
                logging.warning(f"Could not refresh zone {zone}: {e}")
            await asyncio.sleep(0.5)

        await asyncio.sleep(REFRESH_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-populate primary zone & known signed zones
    try:
        fetch_and_cache_zone(PRIMARY_ZONE)
    except Exception as e:
        logging.error(f"Initial fetch for primary zone {PRIMARY_ZONE} failed: {e}")

    asyncio.create_task(refresh_all_zones())
    yield


app = FastAPI(
    title="DNSSEC Trust Anchor Publisher",
    version="2.0",
    description="Publishes RFC 7958 DNSSEC trust anchor XML files for .in and sub-zones.",
    contact={
        "name": "India Internet Foundation",
        "url": "https://trust.aiori.in",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan
)


@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "cached_zones": list(ZONE_CACHE.keys()),
        "refresh_interval": REFRESH_INTERVAL,
        "primary_zone": PRIMARY_ZONE,
        "endpoint": ENDPOINT
    }


@app.get("/in-zone/")
@app.get("/in-zone/index")
async def zone_index(request: Request):
    """HTML / JSON index of available .in zone trust anchors."""
    base = str(request.base_url).rstrip("/")
    items = []
    for z in ALL_IN_ZONES:
        slug = zone_to_slug(z)
        is_signed = z in KNOWN_SIGNED_ZONES or (z in ZONE_CACHE and ZONE_CACHE[z]["xml"] is not None)
        items.append({
            "zone": z,
            "filename": slug,
            "url": f"{base}/in-zone/{slug}",
            "status": "Signed & Available" if is_signed else "Unsigned / No DS Record"
        })

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(items)

    html_lines = [
        "<!DOCTYPE html><html><head><title>DNSSEC Trust Anchors (.in)</title>",
        "<style>body{font-family:sans-serif;margin:2rem;background:#0f172a;color:#f8fafc;}",
        "table{border-collapse:collapse;width:100%;max-width:900px;margin-top:1rem;}",
        "th,td{padding:0.75rem 1rem;border-bottom:1px solid #334155;text-align:left;}",
        "th{background:#1e293b;color:#94a3b8;}",
        "a{color:#38bdf8;text-decoration:none;} a:hover{text-decoration:underline;}",
        ".badge-signed{color:#4ade80;font-weight:600;} .badge-unsigned{color:#f87171;}",
        "</style></head><body>",
        "<h1>DNSSEC Trust Anchors (.in Zones)</h1>",
        "<p>Standard RFC 7958 XML Trust Anchors for .in second-level zones.</p>",
        "<table><thead><tr><th>Zone</th><th>XML Endpoint</th><th>Status</th></tr></thead><tbody>"
    ]
    for item in items:
        status_cls = "badge-signed" if "Signed" in item["status"] else "badge-unsigned"
        html_lines.append(
            f"<tr><td><strong>{item['zone']}</strong></td>"
            f"<td><a href='/in-zone/{item['filename']}'>/in-zone/{item['filename']}</a></td>"
            f"<td><span class='{status_cls}'>{item['status']}</span></td></tr>"
        )
    html_lines.append("</tbody></table></body></html>")
    return HTMLResponse("".join(html_lines))


@app.get("/in-zone/{filename:path}")
async def get_in_zone_trust_anchor(filename: str):
    """
    Serves XML trust anchor for URLs like:
    /in-zone/in.xml
    /in-zone/co-in.xml
    /in-zone/gov-in.xml
    /in-zone/ac-in.xml
    """
    zone = slug_to_zone(filename)

    # Check cache
    cached = ZONE_CACHE.get(zone)
    if cached and cached.get("xml"):
        return Response(content=cached["xml"], media_type="application/xml")

    # Fetch on demand
    try:
        xml_content = fetch_and_cache_zone(zone)
        return Response(content=xml_content, media_type="application/xml")
    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to generate Trust Anchor for zone '{zone}': {str(e)}"
        )


@app.get("/{filename:path}")
async def get_root_trust_anchor(filename: str):
    """Fallback handler for single endpoint paths like /in.xml, /co-in.xml, or /trust-anchor.xml"""
    if filename in ("healthz", "docs", "openapi.json", "favicon.ico"):
        raise HTTPException(status_code=404, detail="Not found")

    zone = slug_to_zone(filename)

    cached = ZONE_CACHE.get(zone)
    if cached and cached.get("xml"):
        return Response(content=cached["xml"], media_type="application/xml")

    try:
        xml_content = fetch_and_cache_zone(zone)
        return Response(content=xml_content, media_type="application/xml")
    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Unable to generate Trust Anchor for '{filename}': {str(e)}"
        )

