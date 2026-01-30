#!/usr/bin/env python3
import asyncio
import hashlib
import json
import os
import random
import re
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import httpx
import websockets
from coincurve import PrivateKey

# -------------------------
# Paste your relay list here
# -------------------------
NOSTR_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.snort.social",
    "wss://nostr.mom",
    "wss://relay.primal.net",

    "wss://relay.nostr.net",
    "wss://relay.current.fyi",
    "wss://relay.nostr.info",
    "wss://relay.nostrich.de",
    "wss://relay.wellorder.net",
    "wss://nostr.rocks",
    "wss://relay.nostr.pub",
    "wss://relay.nostr.dev.br",

    "wss://offchain.pub",
    "wss://soloco.nl",
    "wss://nostr21.com",
    "wss://relay.nostr.bg",
    "wss://nostr.oxtr.dev",
    "wss://relay.plebstr.com",

    "wss://nostr-pub.wellorder.net",
    "wss://relay.nostr.band",
    "wss://cache1.primal.net",
    "wss://purplepag.es",
    "wss://wot.nostr.party",
    "wss://nostr.mutinywallet.com",
    "wss://relay.bitcoiner.social",
    "wss://nostr.bitcoiner.social",
]

# -------------
# Output files
# -------------
GOOD_FILE = "good_relays.txt"
BAD_FILE = "bad_relays.txt"
REPORT_FILE = "relay_report.json"

# -----------------
# Tuning parameters
# -----------------
CONCURRENCY = 8                 # limit parallel relay tests
WS_OPEN_TIMEOUT = 8.0
WS_RECV_WINDOW_S = 2.5
NIP11_TIMEOUT = 6.0
REQ_BURST = 6                   # how many REQs to send in a burst (keep modest)
REQUIRE_NO_AUTH_POW_FOR_GOOD = True  # set True if you want "good" to exclude relays requiring auth/PoW (based on NIP-11)
DO_WRITE_TEST = True            # signed EVENT publish test
WRITE_TIMEOUT_S = 3.0           # wait for OK after EVENT
POW_MAX_DIFFICULTY_TO_ATTEMPT = 14  # higher = expensive
POW_MAX_WORK_MS = 400           # hard cap per relay on PoW mining attempt

RATE_HINT_RE = re.compile(r"(rate|too many|throttle|limit|slow down|flood|spam|busy|overload)", re.I)
AUTH_HINT_RE = re.compile(r"(auth|authenticate|forbidden|401|signature|nip-42|login)", re.I)
POW_HINT_RE = re.compile(r"(pow|difficulty|nonce|nip-13)", re.I)

# websocket close codes you’ll commonly see
POLICY_CLOSE_CODES = {1008}   # policy violation
TRY_LATER_CODES = {1013}      # try again later (RFC)
NORMAL_CLOSE = {1000}

def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        x = x.strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out

def wss_to_https(relay: str) -> str:
    if relay.startswith("wss://"):
        return "https://" + relay[len("wss://"):]
    if relay.startswith("ws://"):
        return "http://" + relay[len("ws://"):]
    return relay

def now_ts() -> int:
    return int(time.time())

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def nip01_event_id(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> str:
    payload = [0, pubkey_hex, created_at, kind, tags, content]
    s = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_hex(s)

def sign_event(priv: PrivateKey, event_id_hex: str) -> str:
    # coincurve returns compact signature (64 bytes) by default; Nostr wants 64-byte schnorr ideally,
    # but most relays accept secp256k1 ECDSA? In Nostr, sig is 64-byte schnorr (BIP340).
    # coincurve supports schnorr via sign_schnorr.
    msg = bytes.fromhex(event_id_hex)
    sig = priv.sign_schnorr(msg, None)
    return sig.hex()

def pubkey_hex_from_priv(priv: PrivateKey) -> str:
    # Nostr pubkey is 32-byte x-only (schnorr pubkey)
    return priv.public_key.format(compressed=False)[1:33].hex()

def nip13_pow_ok(event_id_hex: str, difficulty: int) -> bool:
    # NIP-13 uses leading zero bits in the event id
    if difficulty <= 0:
        return True
    b = bytes.fromhex(event_id_hex)
    bits = "".join(f"{byte:08b}" for byte in b)
    return bits.startswith("0" * difficulty)

def mine_pow(priv: PrivateKey, base_tags: list, content: str, difficulty: int, max_work_ms: int) -> Tuple[list, str]:
    """
    Attempt to add ["nonce", "<n>", "<difficulty>"] tag and find event id with required leading zero bits.
    Returns (tags, event_id_hex). If not found within budget, returns best-effort (nonce included but not meeting).
    """
    if difficulty <= 0:
        pub = pubkey_hex_from_priv(priv)
        created_at = now_ts()
        tags = base_tags[:]
        eid = nip01_event_id(pub, created_at, 1, tags, content)
        return tags, eid

    pub = pubkey_hex_from_priv(priv)
    start = time.perf_counter()
    n = random.randint(0, 10_000_000)

    best_tags = base_tags[:]
    best_id = ""

    # keep created_at stable during mining window to avoid changes
    created_at = now_ts()

    while (time.perf_counter() - start) * 1000.0 < max_work_ms:
        tags = base_tags[:] + [["nonce", str(n), str(difficulty)]]
        eid = nip01_event_id(pub, created_at, 1, tags, content)

        # record last tried
        best_tags, best_id = tags, eid

        if nip13_pow_ok(eid, difficulty):
            return tags, eid

        n += 1

    return best_tags, best_id

@dataclass
class RelayResult:
    relay: str

    # NIP-11
    nip11_ok: bool
    auth_required: Optional[bool]
    min_pow_difficulty: Optional[int]
    limitation: Dict[str, Any]

    # WS
    ws_ok: bool
    connect_ms: Optional[int]
    close: Optional[str]

    # Read probe
    read_burst_ok: bool
    notices: List[str]

    # Write probe
    write_test_ran: bool
    write_ok: Optional[bool]
    write_reason: Optional[str]
    ok_frame: Optional[list]

    # Classification
    good: bool
    good_reason: str

    error: Optional[str]

async def fetch_nip11(relay: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    url = wss_to_https(relay).rstrip("/")
    headers = {"Accept": "application/nostr+json"}
    try:
        async with httpx.AsyncClient(timeout=NIP11_TIMEOUT, follow_redirects=True) as client:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict):
                return False, {}, "NIP-11 response not a JSON object"
            return True, data, None
    except Exception as e:
        return False, {}, str(e)

def parse_policy(nip11_ok: bool, nip11: Dict[str, Any]) -> Tuple[Optional[bool], Optional[int], Dict[str, Any]]:
    auth_required = None
    min_pow = None
    limitation: Dict[str, Any] = {}
    if nip11_ok:
        lim = nip11.get("limitation") or {}
        if isinstance(lim, dict):
            limitation = lim
            if "auth_required" in lim:
                auth_required = bool(lim["auth_required"])
            if "min_pow_difficulty" in lim:
                try:
                    min_pow = int(lim["min_pow_difficulty"])
                except Exception:
                    min_pow = None
    return auth_required, min_pow, limitation

def summarize_close(cc: websockets.ConnectionClosed) -> str:
    return f"closed code={cc.code} reason={cc.reason}"

def notice_flags(notices: List[str]) -> Dict[str, bool]:
    blob = " | ".join(notices)
    return {
        "rate": bool(RATE_HINT_RE.search(blob)),
        "auth": bool(AUTH_HINT_RE.search(blob)),
        "pow": bool(POW_HINT_RE.search(blob)),
    }

async def read_probe(ws) -> Tuple[bool, List[str], Optional[str]]:
    notices: List[str] = []
    close_info: Optional[str] = None

    # Send a small burst of REQs (low impact)
    for i in range(REQ_BURST):
        sub_id = f"probe{i}"
        msg = ["REQ", sub_id, {"kinds": [1], "limit": 1}]
        await ws.send(json.dumps(msg))

    end = time.perf_counter() + WS_RECV_WINDOW_S
    while time.perf_counter() < end:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=0.35)
        except asyncio.TimeoutError:
            continue
        except websockets.ConnectionClosed as cc:
            close_info = summarize_close(cc)
            break

        try:
            frame = json.loads(raw)
            if isinstance(frame, list) and frame:
                if frame[0] == "NOTICE" and len(frame) >= 2:
                    notices.append(str(frame[1]))
        except Exception:
            pass

    flags = notice_flags(notices)
    # Read burst considered ok if we didn't get closed and no rate-limit notice
    read_ok = (close_info is None) and (not flags["rate"])
    return read_ok, notices[:8], close_info

async def write_probe(ws, nip11_min_pow: Optional[int]) -> Tuple[bool, Optional[bool], Optional[str], Optional[list]]:
    """
    Publish a signed kind:1 event and wait for OK.
    Optionally attempt PoW if advertised and <= POW_MAX_DIFFICULTY_TO_ATTEMPT.
    """
    if not DO_WRITE_TEST:
        return False, None, None, None

    priv = PrivateKey(os.urandom(32))
    pub = pubkey_hex_from_priv(priv)
    created_at = now_ts()
    content = f"relay probe {created_at} {random.randint(1000,9999)}"
    base_tags: list = []

    # PoW attempt if relay advertises it and it's not too high
    tags = base_tags[:]
    eid = nip01_event_id(pub, created_at, 1, tags, content)

    if nip11_min_pow is not None and nip11_min_pow > 0 and nip11_min_pow <= POW_MAX_DIFFICULTY_TO_ATTEMPT:
        tags, eid = mine_pow(priv, base_tags, content, nip11_min_pow, POW_MAX_WORK_MS)

    sig = sign_event(priv, eid)
    event = {
        "id": eid,
        "pubkey": pub,
        "created_at": created_at,
        "kind": 1,
        "tags": tags,
        "content": content,
        "sig": sig,
    }

    await ws.send(json.dumps(["EVENT", event]))

    # Wait briefly for OK / NOTICE / close
    end = time.perf_counter() + WRITE_TIMEOUT_S
    last_notice = None
    ok_frame = None
    close_info = None

    while time.perf_counter() < end:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        except websockets.ConnectionClosed as cc:
            close_info = summarize_close(cc)
            break

        try:
            frame = json.loads(raw)
        except Exception:
            continue

        if isinstance(frame, list) and frame:
            if frame[0] == "OK" and len(frame) >= 4:
                # ["OK", <event_id>, <true/false>, <message>]
                ok_frame = frame
                accepted = bool(frame[2])
                msg = str(frame[3])
                reason = msg
                # classify reason hints
                if RATE_HINT_RE.search(msg):
                    reason = "rate_limited: " + msg
                elif AUTH_HINT_RE.search(msg):
                    reason = "auth_required_or_denied: " + msg
                elif POW_HINT_RE.search(msg):
                    reason = "pow_required_or_invalid: " + msg
                elif "invalid" in msg.lower():
                    reason = "invalid_event: " + msg
                return True, accepted, reason, ok_frame

            if frame[0] == "NOTICE" and len(frame) >= 2:
                last_notice = str(frame[1])

    if close_info:
        return True, False, f"closed_before_ok ({close_info})", ok_frame
    if last_notice:
        # no OK but got a notice
        return True, False, f"notice_without_ok ({last_notice})", ok_frame

    # No response — some relays are slow or don't send OK reliably
    return True, None, "no_ok_response", ok_frame

def classify(
    nip11_ok: bool,
    auth_required: Optional[bool],
    min_pow: Optional[int],
    ws_ok: bool,
    close_info: Optional[str],
    read_ok: bool,
    notices: List[str],
    write_ran: bool,
    write_ok: Optional[bool],
    write_reason: Optional[str],
) -> Tuple[bool, str]:
    if not ws_ok:
        return False, "ws_connect_failed"

    # if it closes immediately under light probe, it's bad for you
    if close_info is not None:
        # Prefer close code meaning if present
        m = re.search(r"code=(\d+)", close_info)
        if m:
            code = int(m.group(1))
            if code in POLICY_CLOSE_CODES:
                return False, "closed_policy(1008)"
            if code in TRY_LATER_CODES:
                return False, "closed_try_later(1013)"
        return False, "closed_during_probe"

    flags = notice_flags(notices)
    if flags["rate"]:
        return False, "rate_limit_notice"

    if REQUIRE_NO_AUTH_POW_FOR_GOOD and nip11_ok:
        if auth_required is True:
            return False, "nip11_auth_required"
        if min_pow not in (None, 0):
            return False, f"nip11_pow_required({min_pow})"

    # If you enabled write tests, treat explicit write rejection by auth/pow/rate as "bad" for write-capable list
    # but allow unknown/no_ok_response to pass as long as reads are ok.
    if write_ran:
        if write_ok is True:
            return True, "ok_read+write"
        if write_ok is False:
            # explicit negative
            if write_reason:
                if "rate_limited" in write_reason:
                    return False, "write_rate_limited"
                if "auth_required" in write_reason:
                    return False, "write_auth_required"
                if "pow_required" in write_reason:
                    return False, "write_pow_required"
                if "invalid_event" in write_reason:
                    # If it says invalid, could be strict, but we are signing correctly.
                    # Still treat as bad because publish pipeline is broken/filtered.
                    return False, "write_invalid_event"
            return False, "write_rejected"
        # write_ok is None: no OK response; don't fail solely on that
        return True, "ok_read_write_unknown"

    # no write test
    if read_ok:
        return True, "ok_read"
    return False, "read_probe_failed"

async def check_one(relay: str, sem: asyncio.Semaphore) -> RelayResult:
    async with sem:
        nip11_ok, nip11_data, nip11_err = await fetch_nip11(relay)
        auth_required, min_pow, limitation = parse_policy(nip11_ok, nip11_data)

        t0 = time.perf_counter()
        ws_ok = False
        connect_ms: Optional[int] = None
        close_info: Optional[str] = None
        notices: List[str] = []
        read_ok = False

        write_ran = False
        write_ok: Optional[bool] = None
        write_reason: Optional[str] = None
        ok_frame: Optional[list] = None

        ws_err: Optional[str] = None

        try:
            async with websockets.connect(relay, open_timeout=WS_OPEN_TIMEOUT, close_timeout=2) as ws:
                ws_ok = True
                connect_ms = int((time.perf_counter() - t0) * 1000)

                # Read probe
                read_ok, notices, close_info = await read_probe(ws)

                # Write probe (optional)
                write_ran, write_ok, write_reason, ok_frame = await write_probe(ws, min_pow)

        except websockets.ConnectionClosed as cc:
            close_info = summarize_close(cc)
            ws_err = close_info
        except Exception as e:
            ws_err = str(e)

        good, good_reason = classify(
            nip11_ok=nip11_ok,
            auth_required=auth_required,
            min_pow=min_pow,
            ws_ok=ws_ok,
            close_info=close_info,
            read_ok=read_ok,
            notices=notices,
            write_ran=write_ran,
            write_ok=write_ok,
            write_reason=write_reason,
        )

        error = ws_err or (nip11_err if not nip11_ok else None)

        return RelayResult(
            relay=relay,
            nip11_ok=nip11_ok,
            auth_required=auth_required,
            min_pow_difficulty=min_pow,
            limitation=limitation,

            ws_ok=ws_ok,
            connect_ms=connect_ms,
            close=close_info,

            read_burst_ok=read_ok,
            notices=notices,

            write_test_ran=write_ran,
            write_ok=write_ok,
            write_reason=write_reason,
            ok_frame=ok_frame,

            good=good,
            good_reason=good_reason,

            error=error,
        )

async def main() -> None:
    relays = dedupe_keep_order(NOSTR_RELAYS)
    sem = asyncio.Semaphore(CONCURRENCY)

    print(f"Testing {len(relays)} relays with concurrency={CONCURRENCY}")
    print(f"- write test: {DO_WRITE_TEST}")
    print(f"- require_no_auth_pow_for_good: {REQUIRE_NO_AUTH_POW_FOR_GOOD}")
    print()

    results = await asyncio.gather(*[check_one(r, sem) for r in relays])

    good_lines: List[str] = []
    bad_lines: List[str] = []

    for r in results:
        ms = f"{r.connect_ms}ms" if r.connect_ms is not None else "-"
        nip = "NIP11" if r.nip11_ok else "noNIP11"
        wr = "no-write"
        if r.write_test_ran:
            if r.write_ok is True:
                wr = "write=OK"
            elif r.write_ok is False:
                wr = f"write=NO({r.write_reason})"
            else:
                wr = "write=?"

        line = f"{r.relay}  # {r.good_reason} | ws={'OK' if r.ws_ok else 'FAIL'}({ms}) {nip} auth={r.auth_required} pow={r.min_pow_difficulty} {wr}"
        if r.good:
            good_lines.append(line)
        else:
            bad_lines.append(line)

        print(("-" if r.good else "!"), line)
        if r.notices:
            print(f"    notices: {r.notices}")
        if r.close:
            print(f"    close: {r.close}")
        if r.error and not r.ws_ok:
            print(f"    error: {r.error}")

    with open(GOOD_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(good_lines) + ("\n" if good_lines else ""))
    with open(BAD_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(bad_lines) + ("\n" if bad_lines else ""))
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    print()
    print(f"Wrote {GOOD_FILE} ({len(good_lines)}) and {BAD_FILE} ({len(bad_lines)})")
    print(f"Wrote full JSON report to {REPORT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
