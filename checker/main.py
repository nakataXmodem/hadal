import asyncio
import json
import logging
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_logger() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )


async def fetch(
    session: aiohttp.ClientSession,
    url: str,
    timeout_secs: float,
) -> Tuple[Optional[int], Dict[str, str], Optional[str]]:
    start = time.monotonic()
    try:
        async with session.get(url, allow_redirects=True, timeout=timeout_secs) as resp:
            text = await resp.text(errors="ignore")
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logging.info("GET %s -> %d in %dms", url, resp.status, elapsed_ms)
            # Normalize headers to dict[str,str]
            headers = {k: v for k, v in resp.headers.items()}
            return resp.status, headers, text
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logging.debug("GET %s failed in %dms: %s", url, elapsed_ms, exc)
        return None, {}, None


def extract_title(html: Optional[str]) -> Optional[str]:
    if not isinstance(html, str):
        return None
    try:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if not m:
            return None
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        return title
    except Exception:
        return None


def matches_criteria(
    url: str,
    status: Optional[int],
    headers: Dict[str, str],
    body: Optional[str],
    title: Optional[str],
    criteria: Dict[str, Any],
) -> bool:
    if not criteria:
        return False

    def contains(value: Optional[str], needle: Optional[str]) -> bool:
        if not needle:
            return True
        if value is None:
            return False
        return needle.lower() in value.lower()

    def regex_match(value: Optional[str], pattern: Optional[str]) -> bool:
        if not pattern:
            return True
        if value is None:
            return False
        try:
            return re.search(pattern, value, re.IGNORECASE | re.DOTALL) is not None
        except re.error:
            return False

    checks: List[bool] = []

    # Status checks
    status_in = criteria.get("status_in")
    if isinstance(status_in, list) and len(status_in) > 0:
        checks.append(status in set(status_in))

    status_equals = criteria.get("status_equals")
    if isinstance(status_equals, int):
        checks.append(status == int(status_equals))

    # Title checks
    title_contains_val = criteria.get("title_contains")
    if isinstance(title_contains_val, str) and title_contains_val != "":
        checks.append(contains(title, title_contains_val))

    title_regex_val = criteria.get("title_regex")
    if isinstance(title_regex_val, str) and title_regex_val != "":
        checks.append(regex_match(title, title_regex_val))

    # Body checks
    body_contains_val = criteria.get("body_contains")
    if isinstance(body_contains_val, str) and body_contains_val != "":
        checks.append(contains(body, body_contains_val))

    body_regex_val = criteria.get("body_regex")
    if isinstance(body_regex_val, str) and body_regex_val != "":
        checks.append(regex_match(body, body_regex_val))

    # Headers checks (substring or regex per header)
    hdr_contains: Dict[str, Optional[str]] = criteria.get("headers_contains", {}) or {}
    for hk, hv in hdr_contains.items():
        if not isinstance(hv, str) or hv == "":
            continue
        value = None
        for key, val in headers.items():
            if key.lower() == hk.lower():
                value = val
                break
        checks.append(contains(value, hv))

    hdr_regex: Dict[str, Optional[str]] = criteria.get("headers_regex", {}) or {}
    for hk, pattern in hdr_regex.items():
        if not isinstance(pattern, str) or pattern == "":
            continue
        value = None
        for key, val in headers.items():
            if key.lower() == hk.lower():
                value = val
                break
        checks.append(regex_match(value, pattern))

    # Banner is typically "Server" header
    banner_contains_val = criteria.get("banner_contains")
    banner_regex_val = criteria.get("banner_regex")
    if (isinstance(banner_contains_val, str) and banner_contains_val != "") or (
        isinstance(banner_regex_val, str) and banner_regex_val != ""
    ):
        banner_val = None
        for key, val in headers.items():
            if key.lower() == "server":
                banner_val = val
                break
        if isinstance(banner_contains_val, str) and banner_contains_val != "":
            checks.append(contains(banner_val, banner_contains_val))
        if isinstance(banner_regex_val, str) and banner_regex_val != "":
            checks.append(regex_match(banner_val, banner_regex_val))

    # Match mode: any or all
    mode = (criteria.get("match_mode") or "any").lower()
    effective_checks = [c for c in checks if c is not None]
    if not effective_checks:
        return False
    if mode == "all":
        return all(effective_checks)
    if mode in ("not", "exclude"):
        return not any(effective_checks)
    return any(effective_checks)


async def worker(
    url: str,
    session: aiohttp.ClientSession,
    timeout_secs: float,
    criteria: Dict[str, Any],
    results: List[Dict[str, Any]],
    semaphore: asyncio.Semaphore,
) -> None:
    async with semaphore:
        status, headers, body = await fetch(session, url, timeout_secs)
        title = extract_title(body)
        if matches_criteria(url, status, headers, body, title, criteria):
            results.append(
                {
                    "url": url,
                    "status": status,
                    "title": title,
                    "banner": headers.get("Server") if headers else None,
                }
            )


async def run(config: Dict[str, Any]) -> int:
    input_path = config.get("input_file")
    output_path = config.get("output_file")
    if not input_path or not output_path:
        logging.error("input_file and output_file must be specified in config.json")
        return 2

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            urls: List[str] = json.load(f)
    except Exception as exc:
        logging.error("Failed to read input file %s: %s", input_path, exc)
        return 2

    concurrency = int(config.get("concurrency") or 50)
    timeout_secs = float(config.get("timeout_secs") or 10)
    headers_cfg: Dict[str, str] = config.get("default_headers") or {}
    criteria = config.get("criteria") or {}

    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    results: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(connector=connector, headers=headers_cfg) as session:
        tasks = [
            asyncio.create_task(worker(url, session, timeout_secs, criteria, results, semaphore))
            for url in urls
        ]
        await asyncio.gather(*tasks)

    # Write detected URLs
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        logging.info("Wrote %d detected links to %s", len(results), output_path)
    except Exception as exc:
        logging.error("Failed to write output file %s: %s", output_path, exc)
        return 2

    return 0


def main(argv: List[str]) -> int:
    build_logger()
    config_path = os.getenv("CHECKER_CONFIG", None)
    if not config_path:
        # Default to checker/config.json next to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "config.json")
    if len(argv) > 1:
        # allow custom config path as first arg
        config_path = argv[1]

    try:
        config = load_config(config_path)
    except Exception as exc:
        logging.error("Failed to load config %s: %s", config_path, exc)
        return 2

    return asyncio.run(run(config))


if __name__ == "__main__":
    sys.exit(main(sys.argv))


