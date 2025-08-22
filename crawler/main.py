import asyncio
import ipaddress
import json
import os
import traceback
from typing import Dict, List, Optional, Tuple

import aiohttp
import logging
import time
from collections import defaultdict
import ssl
import re
from urllib.parse import urljoin
from blake3 import blake3
import argparse

from config import *

# Basic logging setup
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)

async def send_telegram_notification(message: str, parse_mode: str = "HTML") -> bool:
    """Send a message to Telegram bot"""
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID and NOTIFY_ON_CRAWLER_ERRORS):
        return False
        
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": parse_mode
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data, timeout=10) as response:
                if response.status == 200:
                    logging.info("Telegram notification sent successfully")
                    return True
                else:
                    logging.error(f"Failed to send Telegram notification: {response.status}")
                    return False
                    
    except Exception as e:
        logging.error(f"Error sending Telegram notification: {e}")
        return False

async def send_error_notification(error: Exception, context: str = "", additional_info: Optional[dict] = None) -> bool:
    """Send an error notification to Telegram"""
    if not NOTIFY_ON_CRAWLER_ERRORS:
        return False
        
    try:
        # Format the error message
        error_type = type(error).__name__
        error_message = str(error)
        traceback_text = traceback.format_exc()
        
        # Build the message
        message_parts = [
            f"🚨 <b>Crawler Error Alert</b>",
            f"<b>Context:</b> {context}",
            f"<b>Error Type:</b> {error_type}",
            f"<b>Error Message:</b> {error_message}"
        ]
        
        if additional_info:
            for key, value in additional_info.items():
                message_parts.append(f"<b>{key}:</b> {value}")
        
        # Add traceback (truncated if too long)
        if traceback_text:
            # Telegram has a 4096 character limit, so truncate if needed
            max_traceback_length = 2000
            if len(traceback_text) > max_traceback_length:
                traceback_text = traceback_text[:max_traceback_length] + "\n... (truncated)"
            message_parts.append(f"<b>Traceback:</b>\n<code>{traceback_text}</code>")
        
        message = "\n".join(message_parts)
        
        return await send_telegram_notification(message)
        
    except Exception as e:
        logging.error(f"Error formatting Telegram notification: {e}")
        return False

async def claim_block(session: aiohttp.ClientSession) -> Optional[Dict]:
    start = time.monotonic()
    headers = {}
    if API_AUTH_TOKEN:
        headers["X-API-Token"] = API_AUTH_TOKEN
    
    try:
        async with session.post(CLAIM_ENDPOINT, headers=headers, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            if resp.status == 404:
                logging.info(f"POST {CLAIM_ENDPOINT} -> 404 in {elapsed_ms}ms (no block)")
                return None
            text = await resp.text()
            logging.info(f"POST {CLAIM_ENDPOINT} -> {resp.status} in {elapsed_ms}ms")
            resp.raise_for_status()
            try:
                data = json.loads(text)
            except Exception:
                logging.warning("Failed to decode claim response JSON")
                return None
            return {"id": data.get("id"), "network": data.get("network")}
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logging.error(f"POST {CLAIM_ENDPOINT} failed in {elapsed_ms}ms: {exc}")
        
        # Send error notification
        await send_error_notification(
            error=exc,
            context="Claim Block API Call",
            additional_info={
                "Endpoint": CLAIM_ENDPOINT,
                "Response Time": f"{elapsed_ms}ms",
                "Status Code": getattr(exc, 'status', 'Unknown')
            }
        )
        return None

async def fetch_http(session: aiohttp.ClientSession, url: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[int]]:
    start = time.monotonic()
    try:
        async with session.get(url, allow_redirects=True, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            is_active = True
            headers_text = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
            headers_text = headers_text[:HEADERS_LIMIT]
            text = await resp.text(errors="ignore")
            text = text[:HTTP_LIMIT]
            server_banner = resp.headers.get("Server") or ""
            banner = server_banner[:BANNER_LIMIT] if server_banner else None
            logging.info(f"GET {url} -> {resp.status} in {elapsed_ms}ms")
            certificate = None
            return is_active, banner, text, headers_text, resp.status
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logging.debug(f"GET {url} -> error in {elapsed_ms}ms: {exc}")
        return False, None, None, None, None

async def probe_host(session: aiohttp.ClientSession, ip: str, status_counts: Dict[str, int]) -> List[Dict]:
    results: List[Dict] = []
    http_url = f"http://{ip}:80"
    https_url = f"https://{ip}:443"

    http_ok, http_banner, http_body, http_headers, http_status = await fetch_http(session, http_url)
    if http_status is None:
        status_counts["no_response"] += 1
    else:
        status_counts[str(http_status)] += 1
    if http_ok and http_status is not None:
        title_http = extract_title(http_body) if isinstance(http_body, str) else None
        icon_hash_http = None
        if FETCH_ICON and isinstance(http_body, str):
            href = extract_icon_href(http_body)
            if href:
                icon_hash_http = await fetch_icon_hash(session, http_url, href)
        results.append({
            "ip_address": ip,
            "port": 80,
            "is_active": http_ok,
            "protocol": "tcp",
            "banner": http_banner[:BANNER_LIMIT] if isinstance(http_banner, str) else None,
            "http_response": http_body[:HTTP_LIMIT] if isinstance(http_body, str) else None,
            "headers": http_headers[:HEADERS_LIMIT] if isinstance(http_headers, str) else None,
            "certificate": None,
            "status_code": int(http_status),
            "title": title_http[:512] if isinstance(title_http, str) else None,
            "icon_hash": icon_hash_http[:32] if isinstance(icon_hash_http, str) else None,
        })

    https_ok, https_banner, https_body, https_headers, https_status = await fetch_http(session, https_url)
    if https_status is None:
        status_counts["no_response"] += 1
    else:
        status_counts[str(https_status)] += 1
    cert_text: Optional[str] = None
    if FETCH_CERT and https_status is not None:
        try:
            cert_text = await fetch_tls_certificate_text(ip)
        except Exception:
            cert_text = None
    if https_ok and https_status is not None:
        title_https = extract_title(https_body) if isinstance(https_body, str) else None
        icon_hash_https = None
        if FETCH_ICON and isinstance(https_body, str):
            href = extract_icon_href(https_body)
            if href:
                icon_hash_https = await fetch_icon_hash(session, https_url, href)
        results.append({
            "ip_address": ip,
            "port": 443,
            "is_active": https_ok,
            "protocol": "tcp",
            "banner": https_banner[:BANNER_LIMIT] if isinstance(https_banner, str) else None,
            "http_response": https_body[:HTTP_LIMIT] if isinstance(https_body, str) else None,
            "headers": https_headers[:HEADERS_LIMIT] if isinstance(https_headers, str) else None,
            "certificate": cert_text[:CERT_LIMIT] if isinstance(cert_text, str) else None,
            "status_code": int(https_status),
            "title": title_https[:512] if isinstance(title_https, str) else None,
            "icon_hash": icon_hash_https[:32] if isinstance(icon_hash_https, str) else None,
        })

    return results

async def fetch_tls_certificate_text(ip: str) -> Optional[str]:
    """Perform TLS handshake on 443 and extract CN and SAN DNS names as a compact string."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=context, server_hostname=ip),
            timeout=DEFAULT_TIMEOUT_SECS,
        )
    except Exception:
        return None

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if not ssl_obj:
            return None
        info = ssl_obj.getpeercert()
        if not info:
            return None

        common_name = None
        subject = info.get("subject", [])
        for rdn in subject:
            for (k, v) in rdn:
                if k.lower() == "commonname":
                    common_name = v
                    break
            if common_name:
                break

        san_entries = []
        for t, v in info.get("subjectAltName", []):
            if t == "DNS":
                san_entries.append(v)

        parts = []
        if common_name:
            parts.append(f"CN={common_name}")
        if san_entries:
            shown = san_entries[:20]
            more = len(san_entries) - len(shown)
            san_part = ",".join(shown)
            if more > 0:
                san_part += f",+{more} more"
            parts.append(f"SAN={san_part}")

        result = "; ".join(parts) if parts else None
        return result
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

def extract_title(html: str) -> Optional[str]:
    try:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if not m:
            return None
        title = m.group(1)
        # Collapse whitespace
        title = re.sub(r"\s+", " ", title).strip()
        return title
    except Exception:
        return None

def extract_icon_href(html: str) -> Optional[str]:
    try:
        # Find first <link ... rel="...icon..." ... href="...">
        for m in re.finditer(r"<link\b[^>]*>", html, re.IGNORECASE):
            tag = m.group(0)
            rel_m = re.search(r"rel\s*=\s*([\"\'])(.*?)\1", tag, re.IGNORECASE)
            if not rel_m:
                continue
            rel_val = rel_m.group(2).lower()
            if "icon" not in rel_val:
                continue
            href_m = re.search(r"href\s*=\s*([\"\'])(.*?)\1", tag, re.IGNORECASE)
            if href_m:
                return href_m.group(2)
        return None
    except Exception:
        return None

async def fetch_icon_hash(session: aiohttp.ClientSession, base_url: str, icon_href: str) -> Optional[str]:
    try:
        url = urljoin(base_url, icon_href)
        start = time.monotonic()
        async with session.get(url, allow_redirects=True, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            if resp.status != 200:
                logging.info(f"GET {url} (icon) -> {resp.status} in {elapsed_ms}ms")
                return None
            # Enforce max size
            cl = resp.headers.get("Content-Length")
            if cl and cl.isdigit() and int(cl) > ICON_MAX_BYTES:
                logging.info(f"Skip icon {url}: Content-Length {cl} > {ICON_MAX_BYTES}")
                return None
            data = await resp.content.read(ICON_MAX_BYTES + 1)
            if len(data) > ICON_MAX_BYTES:
                logging.info(f"Skip icon {url}: body exceeds {ICON_MAX_BYTES}")
                return None
            h = blake3(data).digest(length=16).hex()
            logging.info(f"Icon hashed {url} size={len(data)}B in {elapsed_ms}ms")
            return h
    except Exception as exc:
        logging.info(f"GET {icon_href} (icon) -> error: {exc}")
        return None

async def post_results(session: aiohttp.ClientSession, results: List[Dict]) -> None:
    if not results:
        return
    payload = {"responses": results}
    headers = {}
    if API_AUTH_TOKEN:
        headers["X-API-Token"] = API_AUTH_TOKEN
    
    start = time.monotonic()
    try:
        async with session.post(BULK_ENDPOINT, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            body = await resp.text()
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logging.info(f"POST {BULK_ENDPOINT} size={len(results)} -> {resp.status} in {elapsed_ms}ms")
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logging.error(f"POST {BULK_ENDPOINT} size={len(results)} failed in {elapsed_ms}ms: {exc}")
        
        # Send error notification
        await send_error_notification(
            error=exc,
            context="Bulk Upload API Call",
            additional_info={
                "Endpoint": BULK_ENDPOINT,
                "Batch Size": len(results),
                "Response Time": f"{elapsed_ms}ms",
                "Status Code": getattr(exc, 'status', 'Unknown')
            }
        )
        
async def update_block_status(session: aiohttp.ClientSession, block_id: int, status: str) -> None:
    endpoint = os.getenv("BLOCK_STATUS_ENDPOINT", APP_BASE_URL + "/update-block-status")
    payload = {"id": block_id, "status": status}
    headers = {}
    if API_AUTH_TOKEN:
        headers["X-API-Token"] = API_AUTH_TOKEN
    
    start = time.monotonic()
    try:
        async with session.post(endpoint, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            body = await resp.text()
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logging.info(f"POST {endpoint} status={status} -> {resp.status} in {elapsed_ms}ms")
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logging.error(f"POST {endpoint} status={status} failed in {elapsed_ms}ms: {exc}")
        
        # Send error notification
        await send_error_notification(
            error=exc,
            context="Update Block Status API Call",
            additional_info={
                "Endpoint": endpoint,
                "Block ID": block_id,
                "Status": status,
                "Response Time": f"{elapsed_ms}ms",
                "Status Code": getattr(exc, 'status', 'Unknown')
            }
        )

def _chunked(items: List[Dict], chunk_size: int) -> List[List[Dict]]:
    if chunk_size <= 0:
        return [items]
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]

def _sanitize_result_fields(r: Dict) -> None:
    for key, limit in (("banner", BANNER_LIMIT), ("http_response", HTTP_LIMIT), ("headers", HEADERS_LIMIT), ("certificate", CERT_LIMIT), ("title", 512), ("icon_hash", 32)):
        if isinstance(r.get(key), str):
            r[key] = r[key].replace("\x00", "")[:limit]

async def _scan_network(session: aiohttp.ClientSession, net: ipaddress._BaseNetwork) -> Tuple[List[Dict], Dict[str, int]]:
    semaphore = asyncio.Semaphore(CONCURRENCY)
    results: List[Dict] = []
    status_counts: Dict[str, int] = defaultdict(int)

    async def worker(ip_str: str) -> None:
        async with semaphore:
            r = await probe_host(session, ip_str, status_counts)
            results.extend(r)

    tasks = [asyncio.create_task(worker(str(ip))) for ip in net.hosts()]
    await asyncio.gather(*tasks)
    # Trim and sanitize on client side to respect limits and strip NULs
    for r in results:
        _sanitize_result_fields(r)
    return results, status_counts

async def add_network_blocks(session: aiohttp.ClientSession, count: int = 3) -> bool:
    """Add new network blocks via API endpoint"""
    endpoint = os.getenv("ADD_BLOCKS_ENDPOINT", APP_BASE_URL + "/add-network-blocks")
    payload = {"count": count}
    headers = {}
    if API_AUTH_TOKEN:
        headers["X-API-Token"] = API_AUTH_TOKEN
    
    start = time.monotonic()
    try:
        async with session.post(endpoint, json=payload, headers=headers, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            body = await resp.text()
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logging.info(f"POST {endpoint} count={count} -> {resp.status} in {elapsed_ms}ms")
            if resp.status == 200:
                try:
                    data = json.loads(body)
                    logging.info(f"Added {data.get('inserted', 0)} network blocks")
                    return True
                except Exception:
                    logging.warning("Failed to decode add blocks response JSON")
                    return False
            else:
                logging.error(f"Failed to add network blocks: {resp.status} - {body}")
                return False
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logging.error(f"POST {endpoint} count={count} failed in {elapsed_ms}ms: {exc}")
        
        # Send error notification
        await send_error_notification(
            error=exc,
            context="Add Network Blocks API Call",
            additional_info={
                "Endpoint": endpoint,
                "Count": count,
                "Response Time": f"{elapsed_ms}ms",
                "Status Code": getattr(exc, 'status', 'Unknown')
            }
        )
        return False

async def run_once() -> None:
    overall_start = time.monotonic()
    conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY)
    async with aiohttp.ClientSession(connector=conn, headers=DEFAULT_HEADERS) as session:
        try:
            claim = await claim_block(session)
            if not claim:
                print("No block to claim")
                success = await add_network_blocks(session, 3)
                if success:
                    print("Added new blocks, continuing...")
                else:
                    print("Failed to add new blocks")
                return
            network_cidr = claim["network"]
            block_id = claim["id"]

            try:
                net = ipaddress.ip_network(network_cidr, strict=False)
            except Exception as exc:
                print(f"Invalid CIDR: {network_cidr}")
                await send_error_notification(
                    error=exc,
                    context="Invalid Network CIDR",
                    additional_info={"CIDR": network_cidr}
                )
                return

            results, status_counts = await _scan_network(session, net)

            # Post in batches
            batches = _chunked(results, BATCH_SIZE)
            posted_batches = 0
            for idx, batch in enumerate(batches, start=1):
                if not batch:
                    continue
                await post_results(session, batch)
                posted_batches += 1

            overall_ms = int((time.monotonic() - overall_start) * 1000)
            active_count = sum(1 for r in results if r.get("is_active"))
            total_hosts = (net.num_addresses - 2) if net.version == 4 else net.num_addresses
            logging.info(
                "Completed scan of %s: hosts=%d results=%d active=%d batches=%d in %dms",
                network_cidr, total_hosts, len(results), active_count, posted_batches, overall_ms,
            )

            if status_counts:
                dist = ", ".join(f"{k}:{v}" for k, v in sorted(status_counts.items(), key=lambda kv: kv[0]))
                logging.info("HTTP status distribution: %s", dist)

            final_status = "COMPLETED" if posted_batches > 0 else "FAILED"
            await update_block_status(session, int(block_id) if block_id is not None else 0, final_status)
            
        except Exception as exc:
            overall_ms = int((time.monotonic() - overall_start) * 1000)
            logging.error(f"Critical error in run_once: {exc}", exc_info=True)
            
            # Send error notification
            await send_error_notification(
                error=exc,
                context="Crawler Main Loop",
                additional_info={
                    "Execution Time": f"{overall_ms}ms",
                    "Block ID": block_id if 'block_id' in locals() else "Unknown",
                    "Network CIDR": network_cidr if 'network_cidr' in locals() else "Unknown"
                }
            )

async def scan_subnet_arg(subnet_cidr: str) -> None:
    """Scan a provided subnet and post results to host_responses without touching network_blocks."""
    overall_start = time.monotonic()
    try:
        net = ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception:
        print(f"Invalid CIDR: {subnet_cidr}")
        return
    conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY)
    async with aiohttp.ClientSession(connector=conn, headers=DEFAULT_HEADERS) as session:
        results, status_counts = await _scan_network(session, net)
        batches = _chunked(results, BATCH_SIZE)
        posted_batches = 0
        for batch in batches:
            if not batch:
                continue
            await post_results(session, batch)
            posted_batches += 1

        overall_ms = int((time.monotonic() - overall_start) * 1000)
        active_count = sum(1 for r in results if r.get("is_active"))
        total_hosts = (net.num_addresses - 2) if net.version == 4 else net.num_addresses
        logging.info(
            "[subnet] Completed scan of %s: hosts=%d results=%d active=%d batches=%d in %dms",
            subnet_cidr, total_hosts, len(results), active_count, posted_batches, overall_ms,
        )
        if status_counts:
            dist = ", ".join(f"{k}:{v}" for k, v in sorted(status_counts.items(), key=lambda kv: kv[0]))
            logging.info("[subnet] HTTP status distribution: %s", dist)

async def debug_fetch_ip(ip: str) -> None:
    """Fetch a single IP (HTTP/HTTPS) and print all received data for debugging."""
    conn = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(connector=conn, headers=DEFAULT_HEADERS) as session:
        http_url = f"http://{ip}:80"
        https_url = f"https://{ip}:443"

        http_ok, http_banner, http_body, http_headers, http_status = await fetch_http(session, http_url)
        https_ok, https_banner, https_body, https_headers, https_status = await fetch_http(session, https_url)

        cert_text: Optional[str] = None
        if FETCH_CERT and https_ok and https_status is not None:
            try:
                cert_text = await fetch_tls_certificate_text(ip)
            except Exception:
                cert_text = None

        debug_obj = {
            "ip": ip,
            "http": {
                "ok": bool(http_ok),
                "status": http_status,
                "banner": (http_banner or None),
                "headers": (http_headers[:HEADERS_LIMIT] if isinstance(http_headers, str) else None),
                "title": extract_title(http_body)[:512] if isinstance(http_body, str) and extract_title(http_body) else None,
                "body_preview": (http_body[:512] if isinstance(http_body, str) else None),
            },
            "https": {
                "ok": bool(https_ok),
                "status": https_status,
                "banner": (https_banner or None),
                "headers": (https_headers[:HEADERS_LIMIT] if isinstance(https_headers, str) else None),
                "title": extract_title(https_body)[:512] if isinstance(https_body, str) and extract_title(https_body) else None,
                "body_preview": (https_body[:512] if isinstance(https_body, str) else None),
                "certificate": (cert_text[:CERT_LIMIT] if isinstance(cert_text, str) else None),
            },
        }

        # Optionally compute icon hashes if pages were fetched
        if FETCH_ICON and isinstance(http_body, str):
            href = extract_icon_href(http_body)
            if href:
                try:
                    ih = await fetch_icon_hash(session, http_url, href)
                    debug_obj["http"]["icon_hash"] = ih
                except Exception:
                    debug_obj["http"]["icon_hash"] = None
        if FETCH_ICON and isinstance(https_body, str):
            href = extract_icon_href(https_body)
            if href:
                try:
                    ih = await fetch_icon_hash(session, https_url, href)
                    debug_obj["https"]["icon_hash"] = ih
                except Exception:
                    debug_obj["https"]["icon_hash"] = None

        print(json.dumps(debug_obj, indent=2))

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Network crawler")
    sub = p.add_subparsers(dest="command")

    # Default behavior (no subcommand) -> claim block and scan
    scan_subnet = sub.add_parser("scan-subnet", help="Scan a provided subnet CIDR and post host responses")
    scan_subnet.add_argument("cidr", help="CIDR, e.g. 192.168.1.0/24")

    debug_ip = sub.add_parser("debug-ip", help="Fetch a single IP and print all received data")
    debug_ip.add_argument("ip", help="IP address, e.g. 192.168.1.10")

    return p

async def _run_from_args(args) -> None:
    cmd = args.command
    if cmd == "scan-subnet":
        await scan_subnet_arg(args.cidr)
    elif cmd == "debug-ip":
        await debug_fetch_ip(args.ip)
    else:
        while True:
            await run_once()
            print('waiting for a new subnet')
            time.sleep(5)


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()
    asyncio.run(_run_from_args(args))


if __name__ == "__main__":
    main()


