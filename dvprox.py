#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DevDarK Proxy Phantom    ^_~         — 
Advanced CLI Recon Engine (v3.3)
Seed-first architecture • Multi-Target Verification • Smart Support Unit
SalaaM 3LaikoM Pro   #
"""

import os
import re
import csv
import json
import time
import random
import argparse
import asyncio
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import requests
import aiohttp
from aiohttp import ClientTimeout

# Optional: fast event loop on Linux/macOS
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except Exception:
    pass

try:
    from aiohttp_socks import ProxyConnector as SocksConnector
    HAVE_SOCKS = True
except Exception:
    HAVE_SOCKS = False

from fake_useragent import UserAgent
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TimeElapsedColumn, BarColumn, TextColumn
)
from rich import box

# ─────────────────────────────────────────────────────────────────────────────
APP_NAME = "DevDarK Proxy Phantom"
APP_VERSION = "3.3"

console = Console()
ua = UserAgent()

STATE_DIR = Path.home() / ".devdark_proxy_phantom"
STATE_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = STATE_DIR / "history.json"
SOURCE_HEALTH_FILE = STATE_DIR / "source_health.json"

OUTPUT_TXT_DEFAULT = "prox.txt"
OUTPUT_JSON_DEFAULT = "prox.json"
OUTPUT_CSV_DEFAULT  = "prox.csv"

IP_GEO_ENDPOINT = "http://ip-api.com/json/"  # optional geo enrichment

# Curated, frequently-updated sources
DEFAULT_SOURCES = {
    "http_https": [
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://www.proxy-list.download/api/v1/get?type=https",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt",
    ],
    "socks": [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    ]
}

# Verification targets: (name, url, ok_statuses, optional body regex)
TARGETS = [
    ("google",     "https://www.google.com/generate_204", {204, 200}, None),
    ("cloudflare", "https://1.1.1.1/cdn-cgi/trace",        {200},      r"cf-.*?="),
    ("duckduckgo", "https://duckduckgo.com/?q=ping",       {200},      r"DuckDuckGo"),
]

# Content that signals blocks/captchas we want to avoid even if status=200
BLOCK_SIGNS = re.compile(
    r"(captcha|access\s*denied|forbidden|verify\s*you\s*are\s*a\s*human|temporarily\s*blocked)",
    re.IGNORECASE
)

PROXY_RE = re.compile(
    r"^\s*(?P<host>(\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9\-:\.]+):(?P<port>\d{2,5})\s*$"
)

# ─────────────────────────────────────────────────────────────────────────────
def banner():
    os.system("cls" if os.name == "nt" else "clear")
    console.rule(f"[bold red]🛡 {APP_NAME} • Advanced CLI Recon Engine")
    console.print(f"[bold cyan]🚀 Multi-Target Proxy Verifier + Smart Support Unit", justify="center")
    console.print(
        f"[dim]Version {APP_VERSION} — Seed-first pipeline • curated sources • strict verification[/dim]\n",
        justify="center"
    )

def policy_panel(min_success: int, seed_size: int):
    console.print(Panel.fit(
        f"[bold]Strict Policy:[/bold] A proxy is [green]ALIVE[/green] only if it passes "
        f"[bold]{min_success}[/bold] of [bold]{len(TARGETS)}[/bold] targets.\n"
        f"[bold]Seed Stage:[/bold] Only the top [bold]{seed_size}[/bold] quickest proxies (≤1.0s QuickCheck) move to deep verification.",
        title=f"{APP_NAME} Verification Policy",
        border_style="cyan"
    ))

def jitter(base: float, factor: float = 0.25) -> float:
    return base * (1.0 + random.uniform(-factor, factor))

# ── JSON state I/O (renamed to avoid collision with export JSON) ─────────────
def read_json(path: Path) -> Dict:
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def write_json(path: Path, data: Dict):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        console.log(f"[red]{APP_NAME} save failed: {e}")

def load_history() -> Dict[str, Dict]:
    return read_json(HISTORY_FILE)

def save_history(hist: Dict[str, Dict]) -> None:
    write_json(HISTORY_FILE, hist)

def load_source_health() -> Dict[str, Dict]:
    return read_json(SOURCE_HEALTH_FILE)

def save_source_health(sh: Dict[str, Dict]) -> None:
    write_json(SOURCE_HEALTH_FILE, sh)

# ─────────────────────────────────────────────────────────────────────────────
def proxy_key(scheme: str, addr: str) -> str:
    return f"{scheme}://{addr}"

def proxy_ip(addr: str) -> str:
    return addr.split(":")[0]

def classify_speed(lat_ms: float) -> str:
    if lat_ms <= 500: return "FAST"
    if lat_ms <= 1200: return "MEDIUM"
    return "SLOW"

def format_txt_line(scheme: str, addr: str, lat_ms: float, country: Optional[str]) -> str:
    tag = scheme.upper()
    ctry = country or "??"
    return f"{addr} {tag} {int(lat_ms)}ms {ctry}"

# ─────────────────────────────────────────────────────────────────────────────
def fetch_text_sync(url: str, timeout: float) -> Optional[str]:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": ua.random})
        if r.status_code in (200, 204):
            return r.text
    except Exception:
        return None
    return None

def collect_proxies_sync(
    extra_sources: List[str],
    enable_socks: bool,
    limit_per_source: int,
    protocol: str
) -> Tuple[Dict[str, List[str]], Dict[str, int]]:
    console.log(f"[cyan]{APP_NAME} collecting from curated sources…")
    collected = {"http": [], "https": [], "socks4": [], "socks5": []}
    per_source_counts: Dict[str, int] = {}

    sources = list(DEFAULT_SOURCES["http_https"])
    if extra_sources:
        sources.extend(extra_sources)
    socks_sources = list(DEFAULT_SOURCES["socks"]) if enable_socks else []

    # HTTP/HTTPS
    for src in sources:
        text = fetch_text_sync(src, timeout=12)
        if not text:
            console.log(f"[yellow]Source failed[/yellow]: {src}")
            continue
        lines = [ln.strip() for ln in text.splitlines() if ":" in ln]
        if limit_per_source > 0:
            random.shuffle(lines)
            lines = lines[:limit_per_source]
        cnt = 0
        for ln in lines:
            m = PROXY_RE.match(ln)
            if not m:
                continue
            host, port = m.group("host"), int(m.group("port"))
            # Treat list "https" as HTTPS-capable HTTP CONNECT proxy; we still pass proxy as http://host:port
            scheme = "https" if ("https" in src.lower() or port in (443, 8443)) else "http"
            if protocol != "all" and scheme != protocol:
                continue
            collected[scheme].append(f"{host}:{port}")
            cnt += 1
        per_source_counts[src] = cnt

    # SOCKS (optional)
    for src in socks_sources:
        text = fetch_text_sync(src, timeout=12)
        if not text:
            console.log(f"[yellow]SOCKS source failed[/yellow]: {src}")
            continue
        lines = [ln.strip() for ln in text.splitlines() if ":" in ln]
        if limit_per_source > 0:
            random.shuffle(lines)
            lines = lines[:limit_per_source]
        cnt = 0
        for ln in lines:
            m = PROXY_RE.match(ln)
            if not m:
                continue
            host, port = m.group("host"), int(m.group("port"))
            scheme = "socks5" if ("socks5" in src.lower() or port in (1080, 1085)) else "socks4"
            if protocol != "all" and scheme != protocol:
                continue
            collected[scheme].append(f"{host}:{port}")
            cnt += 1
        per_source_counts[src] = cnt

    # Dedup
    for k in list(collected.keys()):
        collected[k] = sorted(list(set(collected[k])))

    return collected, per_source_counts

def print_sources_summary(collected: Dict[str, List[str]], per_source_counts: Dict[str, int], elapsed: float):
    totals = {k: len(v) for k, v in collected.items()}
    total_all = sum(totals.values())

    tbl = Table(title=f"📦 {APP_NAME} Sources Summary", box=box.MINIMAL_DOUBLE_HEAD)
    tbl.add_column("Protocol", justify="center")
    tbl.add_column("Count", justify="right")
    for k in ["http", "https", "socks4", "socks5"]:
        tbl.add_row(k.upper(), str(totals.get(k, 0)))
    tbl.add_row("TOTAL", str(total_all))
    console.print(tbl)
    console.print(f"[dim]Collection time: {elapsed:.2f}s[/dim]\n")

    # Optional per-source table (show top contributors)
    if per_source_counts:
        st = Table(title=f"{APP_NAME} Top Sources (raw hits)", box=box.SIMPLE)
        st.add_column("Source")
        st.add_column("Count", justify="right")
        for src, cnt in sorted(per_source_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
            st.add_row(src, str(cnt))
        console.print(st)
        console.print()

# ─────────────────────────────────────────────────────────────────────────────
def request_kwargs_for_proxy(scheme: str, addr: str) -> Dict:
    """
    aiohttp expects proxy URL as http://host:port for HTTP CONNECT proxies,
    even when the list labels them 'https'. SOCKS handled via connector.
    """
    if scheme in ("http", "https"):
        return {"proxy": f"http://{addr}"}
    return {}

async def build_session_for_proxy(scheme: str, addr: str, total_timeout: float) -> Tuple[Optional[aiohttp.ClientSession], Dict]:
    headers = {
        "User-Agent": ua.random,
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
    }
    try:
        if scheme.startswith("socks"):
            if not HAVE_SOCKS:
                return None, {}
            connector = SocksConnector.from_url(f"{scheme}://{addr}", ttl_dns_cache=60)
            req_kwargs = {}
        else:
            connector = aiohttp.TCPConnector(ttl_dns_cache=60)
            req_kwargs = request_kwargs_for_proxy(scheme, addr)
        session = aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            trust_env=False,
            timeout=ClientTimeout(total=total_timeout)
        )
        return session, req_kwargs
    except Exception:
        return None, {}

async def quickcheck_target(session: aiohttp.ClientSession, req_kwargs: Dict, timeout: float = 1.0) -> Tuple[bool, float, bool]:
    """
    QuickCheck against Google generate_204.
    Returns (ok, latency_ms, blocked_flag)
    """
    url = "https://www.google.com/generate_204"
    t0 = time.perf_counter()
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True, **req_kwargs) as resp:
            status_ok = resp.status in (200, 204)
            text = ""
            try:
                if resp.content_length is None or (resp.content_length or 0) < 2048:
                    text = await resp.text(errors="ignore")
            except Exception:
                text = ""
            blocked = bool(BLOCK_SIGNS.search(text))
            ok = status_ok and not blocked
    except Exception:
        return False, 1e9, False
    return ok, (time.perf_counter() - t0) * 1000.0, blocked

async def prefilter_quickcheck(
    candidates: List[Tuple[str, str]], limit_seed: int,
    concurrency: int, timeout: float
) -> List[Tuple[str, str, float]]:
    """
    candidates: list of (addr, scheme)
    returns top-N seeds as (addr, scheme, latency_ms)
    """
    sem = asyncio.Semaphore(concurrency)
    results: List[Tuple[str, str, float]] = []

    async def worker(addr: str, scheme: str):
        async with sem:
            session, req_kwargs = await build_session_for_proxy(scheme, addr, timeout * 1.5)
            if session is None:
                return
            ok, lat, blocked = await quickcheck_target(session, req_kwargs, timeout=timeout)
            try:
                await session.close()
            except Exception:
                pass
            if ok and lat <= 1000.0:
                results.append((addr, scheme, lat))

    tasks = [worker(addr, scheme) for (addr, scheme) in candidates]
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task("[cyan]Seed QuickCheck (≤1.0s)…", total=len(tasks))
        for fut in asyncio.as_completed(tasks):
            await fut
            prog.update(t, advance=1)

    results.sort(key=lambda x: x[2])
    return results[:limit_seed]

async def check_target(
    session: aiohttp.ClientSession, req_kwargs: Dict,
    url: str, ok_statuses: set, regex: Optional[str], timeout: float
) -> Tuple[bool, float, bool]:
    """
    Returns (success, latency_ms, blocked_flag)
    """
    t0 = time.perf_counter()
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True, **req_kwargs) as resp:
            ok = resp.status in ok_statuses
            text = ""
            try:
                if resp.content_length is None or (resp.content_length or 0) < 4096:
                    text = await resp.text(errors="ignore")
            except Exception:
                text = ""
            body_ok = True
            if regex and ok:
                body_ok = bool(re.search(regex, text, re.IGNORECASE))
            blocked = bool(BLOCK_SIGNS.search(text))
            success = ok and body_ok and not blocked
    except Exception:
        return False, 1e9, False
    return success, (time.perf_counter() - t0) * 1000.0, blocked

async def strict_verify(
    scheme: str, addr: str, per_target_timeout: float,
    min_success: int, retries: int
) -> Dict:
    """
    Returns rich result dict
    """
    result = {
        "key": proxy_key(scheme, addr),
        "scheme": scheme, "addr": addr,
        "ok": False, "successes": 0, "lat_avg": 1e9,
        "targets": {}, "country": None
    }

    best = {"avg": 1e9, "targets": {}, "succ": 0}
    attempt = 0

    while attempt <= retries:
        session, req_kwargs = await build_session_for_proxy(scheme, addr, per_target_timeout * 1.5)
        if session is None:
            break

        local = {}
        succ = 0
        lats = []
        try:
            for (name, url, oks, rgx) in TARGETS:
                ok, lat, blocked = await check_target(session, req_kwargs, url, oks, rgx, per_target_timeout)
                local[name] = {"ok": ok, "lat": lat, "blocked": blocked}
                if ok:
                    succ += 1
                    lats.append(lat)
            await session.close()
        except Exception:
            try:
                await session.close()
            except Exception:
                pass

        if succ >= min_success:
            avg = sum(lats) / len(lats) if lats else 1e9
            if avg < best["avg"]:
                best = {"avg": avg, "targets": local, "succ": succ}
                if avg < 700:  # golden early exit
                    break
        attempt += 1
        if attempt <= retries:
            await asyncio.sleep(jitter(0.30, 0.4))

    if best["succ"] >= min_success:
        result["ok"] = True
        result["successes"] = best["succ"]
        result["lat_avg"] = best["avg"]
        result["targets"] = best["targets"]
    else:
        result["ok"] = False
        result["successes"] = best["succ"]
        result["lat_avg"] = best["avg"] if best["avg"] < 1e9 else 99999.0
        result["targets"] = best["targets"]

    return result

async def geo_enrich(results: List[Dict], timeout: float = 3.0):
    async with aiohttp.ClientSession(timeout=ClientTimeout(total=timeout)) as sess:
        tasks = []
        for r in results:
            if r["ok"]:
                tasks.append(asyncio.create_task(
                    sess.get(IP_GEO_ENDPOINT + proxy_ip(r["addr"]), timeout=timeout)))
            else:
                tasks.append(asyncio.create_task(asyncio.sleep(0, result=None)))
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for r, resp in zip(results, responses):
            if not r["ok"]:
                continue
            try:
                if hasattr(resp, "status") and resp.status == 200:
                    data = await resp.json()
                    r["country"] = data.get("countryCode") or data.get("country")
            except Exception:
                r["country"] = None
            finally:
                try:
                    if hasattr(resp, "release"):
                        await resp.release()
                except Exception:
                    pass

async def verify_stage(
    seeds: List[Tuple[str, str, float]], min_success: int,
    timeout_per_target: float, concurrency: int, retries: int
) -> List[Dict]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []

    async def worker(addr: str, scheme: str):
        async with sem:
            res = await strict_verify(scheme, addr, timeout_per_target, min_success, retries)
            results.append(res)

    tasks = [worker(addr, scheme) for (addr, scheme, _lat) in seeds]
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(), console=console) as prog:
        t = prog.add_task(f"[cyan]{APP_NAME} deep verification…", total=len(tasks))
        for fut in asyncio.as_completed(tasks):
            await fut
            prog.update(t, advance=1)
    return results

# ─────────────────────────────────────────────────────────────────────────────
def smart_sort(combined: List[Tuple[str, str]], hist: Dict[str, Dict]) -> List[Tuple[str, str]]:
    def score_for(key: str) -> float:
        h = hist.get(key)
        if not h:
            return 0.0
        successes = h.get("successes", 0)
        last_score = h.get("score", 0.0)
        lat_ms = h.get("latency_ms", 15000)
        freshness = max(0.0, 1.0 - (time.time() - h.get("ts", 0)) / (7 * 24 * 3600))
        return (successes * 1.5) + last_score + (10000.0 / (1 + lat_ms)) + (freshness * 2.0)
    return sorted(combined, key=lambda pr: score_for(proxy_key(pr[1], pr[0])), reverse=True)

def update_history(results: List[Dict], min_success: int):
    hist = load_history()
    for r in results:
        key = r["key"]
        h = hist.get(key, {})
        h["ts"] = time.time()
        h["successes"] = h.get("successes", 0) + (1 if r["ok"] else 0)
        h["latency_ms"] = int(r["lat_avg"])
        score = (h["successes"] * 2.0) + (3000.0 / (1 + max(1.0, r["lat_avg"])))
        score += (r["successes"] - (min_success - 1)) * 1.25
        h["score"] = round(score, 2)
        hist[key] = h
    save_history(hist)

def record_source_health(per_source_counts: Dict[str, int], pre_count: int, seed_count: int, alive_count: int):
    sh = load_source_health()
    snapshot = {
        "ts": int(time.time()),
        "raw_total": pre_count,
        "seed_total": seed_count,
        "alive_total": alive_count,
        "per_source_raw": per_source_counts
    }
    sh[str(snapshot["ts"])] = snapshot
    save_source_health(sh)

# ─────────────────────────────────────────────────────────────────────────────
def render_dashboard(results: List[Dict], limit_show: int = 120) -> None:
    ok_count = sum(1 for r in results if r["ok"])
    total = len(results)
    table = Table(title=f"🔍 {APP_NAME} Results (alive: {ok_count}/{total})",
                  box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("#", justify="right", style="bold")
    table.add_column("Proxy")
    table.add_column("Proto", justify="center")
    table.add_column("OK", justify="center")
    table.add_column("Successes", justify="center")
    table.add_column("Latency(ms)", justify="right")
    table.add_column("Speed", justify="center")
    table.add_column("Country", justify="center")

    shown = 0
    for i, r in enumerate(results, start=1):
        if shown >= limit_show:
            break
        ok = "✅" if r["ok"] else "❌"
        succ = f"{r['successes']}/{len(TARGETS)}"
        lat = str(int(r["lat_avg"])) if r["lat_avg"] < 1e9 else "-"
        speed = classify_speed(r["lat_avg"]) if r["ok"] else "—"
        country = r.get("country") or "—"
        table.add_row(str(i), r["addr"], r["scheme"].upper(), ok, succ, lat, speed, country)
        shown += 1

    console.print(table)
    if total > shown:
        console.print(f"[dim]Showing first {shown} of {total}…[/dim]")

# ── Exporters (distinct names to avoid collisions with state I/O) ────────────
def export_txt(results: List[Dict], path: str) -> int:
    alive = [r for r in results if r["ok"]]
    lines = [format_txt_line(r["scheme"], r["addr"], r["lat_avg"], r.get("country")) for r in alive]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    return len(lines)

def export_json(results: List[Dict], path: str) -> int:
    alive = [r for r in results if r["ok"]]
    out = [{
        "proxy": r["addr"], "scheme": r["scheme"],
        "latency_ms": int(r["lat_avg"]), "successes": r["successes"],
        "speed": classify_speed(r["lat_avg"]), "country": r.get("country"),
        "targets": r["targets"]
    } for r in alive]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    return len(out)

def export_csv(results: List[Dict], path: str) -> int:
    alive = [r for r in results if r["ok"]]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["proxy", "scheme", "latency_ms", "successes", "speed", "country"])
        for r in alive:
            w.writerow([r["addr"], r["scheme"], int(r["lat_avg"]), r["successes"],
                        classify_speed(r["lat_avg"]), r.get("country") or ""])
    return len(alive)

# ─────────────────────────────────────────────────────────────────────────────
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=f"{APP_NAME} — Seed-first, multi-target proxy verifier")
    # Collection
    p.add_argument("--protocol", choices=["http", "https", "socks4", "socks5", "all"], default="https",
                   help="Filter proxies by protocol at collection time (default: https)")
    p.add_argument("--enable-socks", action="store_true", help="Enable SOCKS verification (needs aiohttp_socks)")
    p.add_argument("--source", action="append", default=[], help="Add custom source (repeatable)")
    p.add_argument("--limit-per-source", type=int, default=0, help="Cap proxies per source before dedup (0=unlimited)")
    # Pre-filter (seed stage)
    p.add_argument("--seed-size", type=int, default=1200, help="How many fastest proxies to deep-check (1000–1500 suggested)")
    p.add_argument("--prefilter", action="store_true", help="Enable QuickCheck pre-filter stage (≤1s)")
    p.add_argument("--prefilter-concurrency", type=int, default=300, help="Concurrency for prefilter stage")
    p.add_argument("--prefilter-timeout", type=float, default=1.0, help="Timeout per QuickCheck request")
    # Deep verification
    p.add_argument("-c", "--concurrency", type=int, default=160, help="Deep verification concurrency")
    p.add_argument("-t", "--timeout", type=float, default=6.0, help="Per-target timeout (seconds)")
    p.add_argument("-r", "--retries", type=int, default=1, help="Retries per proxy during deep verification")
    p.add_argument("-m", "--min-success", type=int, default=2, choices=range(1, len(TARGETS)+1),
                   help=f"Minimum successful targets to accept proxy (1..{len(TARGETS)})")
    p.add_argument("--no-geo", action="store_true", help="Disable Geo enrichment for alive proxies")
    p.add_argument("--limit-total", type=int, default=0, help="Hard cap after collection (0=unlimited)")
    p.add_argument("--show", type=int, default=120, help="Rows to show in dashboard")
    # Outputs
    p.add_argument("-o", "--output", type=str, default=OUTPUT_TXT_DEFAULT, help="TXT output file (default prox.txt)")
    p.add_argument("--json", nargs="?", const=OUTPUT_JSON_DEFAULT, default=None,
                   help="Optional JSON output (use default path if no value provided)")
    p.add_argument("--csv", nargs="?", const=OUTPUT_CSV_DEFAULT, default=None,
                   help="Optional CSV output (use default path if no value provided)")
    return p

# ─────────────────────────────────────────────────────────────────────────────
def main():
    args = build_argparser().parse_args()
    banner()

    if args.enable_socks and not HAVE_SOCKS:
        console.print("[yellow]Note:[/yellow] aiohttp_socks not installed → SOCKS will be ignored.")

    policy_panel(args.min_success, args.seed_size)

    t_collect0 = time.perf_counter()
    collected, per_source_counts = collect_proxies_sync(
        extra_sources=args.source,
        enable_socks=args.enable_socks,
        limit_per_source=args.limit_per_source,
        protocol=args.protocol
    )
    t_collect1 = time.perf_counter()

    print_sources_summary(collected, per_source_counts, t_collect1 - t_collect0)

    # Flatten
    combined: List[Tuple[str, str]] = []
    for scheme, lst in collected.items():
        for addr in lst:
            combined.append((addr, scheme))

    # Dedup across protocols of same addr (prefer https)
    seen = set()
    unique: List[Tuple[str, str]] = []
    for addr, scheme in sorted(combined, key=lambda x: (x[0], 0 if x[1]=="https" else 1)):
        if addr in seen:
            continue
        seen.add(addr)
        unique.append((addr, scheme))

    if args.limit_total and args.limit_total > 0:
        random.shuffle(unique)
        unique = unique[:args.limit_total]

    if not unique:
        console.print(f"[red]{APP_NAME}: no proxies after collection/filtering.[/red]")
        return

    # Smart prioritization from history
    history = load_history()
    unique = smart_sort(unique, history)

    # Pre-filter (seed stage)
    if args.prefilter:
        t_seed0 = time.perf_counter()
        seeds = asyncio.run(prefilter_quickcheck(
            candidates=unique,
            limit_seed=max(1, args.seed_size),
            concurrency=args.prefilter_concurrency,
            timeout=args.prefilter_timeout
        ))
        t_seed1 = time.perf_counter()

        console.print(Panel.fit(
            f"QuickCheck passed: [bold]{len(seeds)}[/bold] seeds ≤ 1.0s "
            f"(from raw [bold]{len(unique)}[/bold]).\n"
            f"[dim]Seed stage time: {(t_seed1 - t_seed0):.2f}s[/dim]",
            title=f"{APP_NAME} Seed Summary", border_style="magenta"
        ))
        if not seeds:
            console.print(f"[red]{APP_NAME}: no seeds passed QuickCheck. Try relaxing seed size/timeout.[/red]")
            return
    else:
        # If prefilter disabled, synthesize seeds by taking top-N from unique
        seeds = [(addr, scheme, 9999.0) for (addr, scheme) in unique[:max(1, args.seed_size)]]

    # Deep verification
    console.print(f"[green]Starting deep verification on {len(seeds)} seeds with concurrency={args.concurrency}…[/green]\n")
    t_verify0 = time.perf_counter()
    results = asyncio.run(verify_stage(
        seeds=seeds,
        min_success=args.min_success,
        timeout_per_target=args.timeout,
        concurrency=args.concurrency,
        retries=args.retries
    ))
    t_verify1 = time.perf_counter()

    # Geo enrichment
    if not args.no_geo:
        asyncio.run(geo_enrich(results, timeout=3.0))

    # Update history and source health snapshot
    update_history(results, args.min_success)
    alive_count = sum(1 for r in results if r["ok"])
    record_source_health(per_source_counts, pre_count=len(unique), seed_count=len(seeds), alive_count=alive_count)

    # Render & save
    render_dashboard(results, limit_show=args.show)

    saved_txt = export_txt(results, args.output)
    msg_lines = [f"[bold green]Saved[/bold green] [bold]{saved_txt}[/bold] alive proxies to: [bold]{args.output}[/bold]"]

    if args.json:
        json_path = args.json
        saved_json = export_json(results, json_path)
        msg_lines.append(f"[cyan]JSON[/cyan]: {saved_json} entries → {json_path}")

    if args.csv:
        csv_path = args.csv
        saved_csv = export_csv(results, csv_path)
        msg_lines.append(f"[cyan]CSV[/cyan]: {saved_csv} rows → {csv_path}")

    console.print(Panel.fit(
        "\n".join(msg_lines) +
        f"\n[cyan]Alive[/cyan]: {alive_count} / [cyan]Verified[/cyan]: {len(results)}"
        f"\n[dim]Collect: {(t_collect1 - t_collect0):.2f}s • Verify: {(t_verify1 - t_verify0):.2f}s[/dim]",
        title=f"{APP_NAME} Final Summary", border_style="green"
    ))

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Terminated by user.[/red]")
    except Exception as e:
        console.print(f"[bold red]Unexpected error → {type(e).__name__}: {e}[/bold red]")
