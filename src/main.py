#!/usr/bin/env python3

import asyncio
from contextlib import asynccontextmanager
import logging
import os
import xml.etree.ElementTree as ET

from fastapi import FastAPI, HTTPException, Response

import dns.name
from dotenv import load_dotenv

import utils


# Load the .env file
load_dotenv()

ENDPOINT = os.getenv("ENDPOINT", "trust-anchor.xml")
SOURCE = os.getenv("SOURCE", "generated")
ZONE = os.getenv("ZONE", "in.")
REFRESH_INTERVAL = 3600  # seconds


global latest_xml, last_refresh, last_error
latest_xml = None
last_refresh = None
last_error = None

async def refresh_xml():
    global latest_xml
    global last_refresh
    global last_error

    while True:

        try:
            zone_name = dns.name.from_text(ZONE)

            dnskey_rrset = utils.get_dnskey_rrset(zone_name)
            ds_rrset = utils.get_ds_rrset(zone_name)

            if not utils.validate_dnskey_ds(
                dnskey_rrset,
                ds_rrset,
                zone_name
            ):
                raise RuntimeError(
                    "DNSKEY/DS validation failed"
                )

            xml_root = utils.build_xml(
                zone_name.to_text(),
                dnskey_rrset,
                ds_rrset,
                source = SOURCE
            )

            xml_bytes = ET.tostring(
                xml_root,
                encoding="utf-8",
                xml_declaration=True
            )

            latest_xml = xml_bytes
            last_refresh = asyncio.get_running_loop().time()
            last_error = None

            logging.info(
                "Trust anchor refreshed successfully"
            )

        except Exception as e:
            last_error = str(e)

            logging.exception(
                "Failed to refresh trust anchor"
            )

        await asyncio.sleep(REFRESH_INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(refresh_xml())
    yield

app = FastAPI(
    title="DNSSEC Trust Anchor Publisher", version="1.0", 
    description="Publishes DNSSEC trust anchor XML for a specified zone.",
    contact={
        "name": "Andrew",
        "email": "",
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
        "status": "ok" if latest_xml else "starting",
        "last_error": last_error,
        "has_xml": latest_xml is not None,
        "endpoint": ENDPOINT,
        "source": SOURCE,
        "zone": ZONE,
        "refresh_interval": REFRESH_INTERVAL
    }


@app.get(f"/{ENDPOINT}")
async def trust_anchor():

    if latest_xml is None:
        raise HTTPException(
            status_code=503,
            detail="Trust anchor not yet available"
        )

    return Response(
        content=latest_xml,
        media_type="application/xml"
    )