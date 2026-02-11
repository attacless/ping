#!/usr/bin/env python3
"""
Manuscrypt Addon for Ping
==============================
Send encrypted files via Manuscrypt.

The encryption happens client-side.
The server never sees plaintext data or encryption keys.

Commands:
  /send [path]      - Browse and send a file
  /send config      - Set your Manuscrypt server URL

Requires: pip install cryptography aiohttp
"""

from __future__ import annotations
import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Callable
from dataclasses import dataclass, field

# Debug flag - set to True to enable verbose logging
DEBUG = False

def debug(msg: str):
    if DEBUG:
        print(f"  [send debug] {msg}", file=sys.stderr)

# Optional imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

def _get_ssl_context():
    """Get best available SSL context (fixes macOS certificate issues)."""
    import ssl as _ssl
    # Method 1: certifi (most reliable on macOS)
    try:
        import certifi
        return _ssl.create_default_context(cafile=certifi.where())
    except (ImportError, Exception):
        pass
    # Method 2: default system certs
    try:
        return _ssl.create_default_context()
    except Exception:
        pass
    # Method 3: unverified (last resort)
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    return ctx

def _get_tcp_connector():
    """Get aiohttp TCPConnector with proper SSL context."""
    return aiohttp.TCPConnector(ssl=_get_ssl_context())

try:
    import curses
    HAS_CURSES = True
except ImportError:
    HAS_CURSES = False

# Ping addon base class (injected at load time)
if 'PingAddon' not in dir():
    class PingAddon:
        name = "Base"
        version = "1.0.1"
        description = ""
        commands = {}
        def __init__(self): self.cli = None
        def on_load(self, cli): self.cli = cli
        def on_unload(self): pass
        def on_message(self, sender, text): pass


# =============================================================================
# Config
# =============================================================================

CONFIG_FILE = Path.home() / ".ping" / "manuscrypt.json"
DEFAULT_SERVER = "https://manuscrypt.xyz"
MAX_FILE_SIZE = 25 * 1024 * 1024

EXPIRY_OPTIONS = [
    ("1h", "1 hour", 3600),
    ("1d", "1 day", 86400),
    ("7d", "7 days", 604800),
    ("21d", "21 days", 1814400),
]


@dataclass 
class Config:
    server_url: str = DEFAULT_SERVER
    
    def save(self):
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps({"server_url": self.server_url}, indent=2))
    
    @classmethod
    def load(cls) -> "Config":
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                return cls(server_url=data.get("server_url", DEFAULT_SERVER))
            except:
                pass
        return cls()


# =============================================================================
# Manuscrypt client-side crypto
# =============================================================================

def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (matches Manuscrypt's toBase64Url)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def sha256_b64url(data: bytes) -> str:
    """SHA-256 hash as base64url (matches Manuscrypt's sha256Base64Url)."""
    return b64url_encode(hashlib.sha256(data).digest())


def encrypt_aes_gcm(plaintext: bytes, passphrase: Optional[str] = None) -> Dict[str, Any]:
    """
    AES-256-GCM encryption
    
    Returns: {ciphertext, iv, key (if no passphrase), kdf (if passphrase)}
    """
    iv = secrets.token_bytes(12)
    
    if passphrase:
        # PBKDF2 key derivation (matches deriveAesGcmFromPassphrase)
        salt = secrets.token_bytes(16)
        iterations = 200000
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        key = kdf.derive(passphrase.encode('utf-8'))
        kdf_params = {
            "name": "PBKDF2",
            "hash": "SHA-256",
            "iterations": iterations,
            "salt": b64url_encode(salt),
        }
    else:
        key = secrets.token_bytes(32)
        kdf_params = None
    
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "key": key if not passphrase else None,
        "kdf": kdf_params,
    }


def build_share_hash(payload: Dict[str, Any]) -> str:
    """Build manuscrypt: share hash"""
    return f"manuscrypt:{b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))}"


# =============================================================================
# Curses File Browser
# =============================================================================

def format_size(size: int) -> str:
    if size < 1024: return f"{size}B"
    if size < 1024**2: return f"{size/1024:.1f}K"
    return f"{size/1024**2:.1f}M"


def browse_files(start_dir: Optional[Path] = None, stdscr=None) -> Optional[Path]:
    """
    Curses file browser. Returns selected file or None.
    If stdscr is provided, uses it directly (ping integration).
    Otherwise falls back to curses.wrapper.
    """
    if not HAS_CURSES:
        return None
    
    state = {"cwd": start_dir or Path.home(), "idx": 0, "scroll": 0, "result": None, "done": False}
    
    def get_entries(path: Path) -> List[Tuple[str, bool, int]]:
        entries = []
        if path.parent != path:
            entries.append(("..", True, 0))
        try:
            for item in sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                if item.name.startswith('.'): continue
                try:
                    is_dir = item.is_dir()
                    size = 0 if is_dir else item.stat().st_size
                    entries.append((item.name, is_dir, size))
                except: pass
        except: pass
        return entries
    
    def run_browser(scr):
        curses.curs_set(0)
        scr.keypad(True)
        scr.nodelay(False)  # Blocking input for file browser
        
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            try:
                curses.init_pair(1, curses.COLOR_CYAN, -1)
                curses.init_pair(2, curses.COLOR_GREEN, -1)
            except:
                pass
        
        while not state["done"]:
            scr.clear()
            h, w = scr.getmaxyx()
            entries = get_entries(state["cwd"])
            if entries:
                state["idx"] = max(0, min(state["idx"], len(entries) - 1))
            else:
                state["idx"] = 0
            
            # Header
            header = f" Select File: {state['cwd']}"
            if len(header) > w - 1:
                header = " Select File: ..." + str(state['cwd'])[-(w-20):]
            try:
                scr.addstr(0, 0, header[:w-1], curses.A_BOLD)
                scr.addstr(1, 0, "-" * (w-1))
            except curses.error:
                pass
            
            # List
            list_h = max(1, h - 5)
            if state["idx"] < state["scroll"]: 
                state["scroll"] = state["idx"]
            if state["idx"] >= state["scroll"] + list_h: 
                state["scroll"] = state["idx"] - list_h + 1
            
            for i, (name, is_dir, size) in enumerate(entries[state["scroll"]:state["scroll"]+list_h]):
                y = 2 + i
                if y >= h - 3:
                    break
                sel = (state["scroll"] + i) == state["idx"]
                
                if is_dir:
                    line = f" {'>' if sel else ' '} [DIR] {name}"
                else:
                    sz_str = format_size(size)
                    line = f" {'>' if sel else ' '}       {name}"
                    pad = w - len(line) - len(sz_str) - 2
                    if pad > 0: 
                        line += " " * pad + sz_str
                
                # Truncate
                line = line[:w-1]
                
                attr = curses.A_REVERSE if sel else 0
                if curses.has_colors() and is_dir: 
                    attr |= curses.color_pair(1)
                try: 
                    scr.addstr(y, 0, line, attr)
                except curses.error: 
                    pass
            
            # Footer
            try:
                scr.addstr(h-3, 0, "-" * (w-1))
                scr.addstr(h-2, 0, " UP/DOWN:Navigate  ENTER:Select  q:Cancel  ~:Home"[:w-1])
            except curses.error:
                pass
            
            scr.refresh()
            
            # Input
            try:
                key = scr.getch()
            except:
                continue
            
            debug(f"browse: key={key}")
            
            if key in (ord('q'), ord('Q'), 27):  # q, Q, ESC
                state["done"] = True
                state["result"] = None
            elif key == curses.KEY_UP or key == ord('k'):
                state["idx"] = max(0, state["idx"]-1)
            elif key == curses.KEY_DOWN or key == ord('j'):
                state["idx"] = min(len(entries)-1, state["idx"]+1) if entries else 0
            elif key == ord('~'):
                state["cwd"], state["idx"], state["scroll"] = Path.home(), 0, 0
            elif key in (10, 13, curses.KEY_ENTER):
                if not entries: 
                    continue
                name, is_dir, size = entries[state["idx"]]
                if name == "..":
                    state["cwd"], state["idx"], state["scroll"] = state["cwd"].parent, 0, 0
                elif is_dir:
                    new_path = state["cwd"] / name
                    if os.access(new_path, os.R_OK | os.X_OK):
                        state["cwd"], state["idx"], state["scroll"] = new_path, 0, 0
                else:
                    if size > MAX_FILE_SIZE: 
                        continue
                    if size == 0:
                        continue
                    state["result"] = state["cwd"] / name
                    state["done"] = True
    
    # If stdscr provided (from ping), use it directly
    if stdscr is not None:
        run_browser(stdscr)
    else:
        # Standalone mode - use wrapper
        try:
            curses.wrapper(run_browser)
        except Exception as e:
            debug(f"browse exception: {e}")
    
    return state["result"]


# =============================================================================
# Options Dialog
# =============================================================================

@dataclass
class ShareOptions:
    expiry_idx: int = 2  # 7 days
    max_downloads: int = 5
    one_time: bool = False
    use_passphrase: bool = False
    passphrase: str = ""
    confirmed: bool = False


def options_dialog(filename: str, filesize: int, stdscr=None) -> Optional[ShareOptions]:
    """
    Curses dialog for share options.
    If stdscr is provided, uses it directly (ping integration).
    """
    if not HAS_CURSES:
        return ShareOptions(confirmed=True)
    
    opts = ShareOptions()
    state = {"field": 0, "done": False}  # 0=expiry, 1=max_dl, 2=one_time, 3=passphrase_toggle, 4=passphrase_input
    
    def run_dialog(scr):
        curses.curs_set(0)
        scr.keypad(True)
        scr.nodelay(False)  # Blocking input
        
        while not state["done"]:
            scr.clear()
            h, w = scr.getmaxyx()
            field = state["field"]
            
            # Center dialog
            dw = min(55, w-4)
            dh = 15
            sy = max(0, (h-dh)//2)
            sx = max(0, (w-dw)//2)
            
            def line(y, txt, hl=False):
                actual_y = sy + y
                if actual_y >= h:
                    return
                if hl: 
                    scr.attron(curses.A_REVERSE)
                try: 
                    scr.addstr(actual_y, sx+1, txt[:dw-2])
                except curses.error: 
                    pass
                if hl: 
                    scr.attroff(curses.A_REVERSE)
            
            # Draw box
            line(0, "+" + "-"*(dw-2) + "+")
            line(1, "|" + " Share Options ".center(dw-2) + "|")
            line(2, "+" + "-"*(dw-2) + "+")
            
            # File info
            fname_display = filename[:dw-12] if len(filename) > dw-12 else filename
            line(3, f"| File: {fname_display}".ljust(dw-1) + "|")
            line(4, f"| Size: {format_size(filesize)}".ljust(dw-1) + "|")
            line(5, "|" + "-"*(dw-2) + "|")
            
            # Expiry (field 0)
            _, exp_label, _ = EXPIRY_OPTIONS[opts.expiry_idx]
            exp_text = f"| Expires: < {exp_label:^10} >"
            line(6, exp_text.ljust(dw-1) + "|", field==0)
            
            # Max downloads (field 1)
            if opts.one_time:
                line(7, "| Max downloads: 1 (one-time)".ljust(dw-1) + "|")
            else:
                max_text = f"| Max downloads: < {opts.max_downloads:^4} >"
                line(7, max_text.ljust(dw-1) + "|", field==1)
            
            # One-time toggle (field 2)
            ot_check = "x" if opts.one_time else " "
            line(8, f"| [{ot_check}] One-time link".ljust(dw-1) + "|", field==2)
            
            # Passphrase toggle (field 3)
            pp_check = "x" if opts.use_passphrase else " "
            line(9, f"| [{pp_check}] Passphrase protection".ljust(dw-1) + "|", field==3)
            
            # Passphrase input (field 4)
            if opts.use_passphrase:
                pdisp = '*' * len(opts.passphrase) if opts.passphrase else "(type passphrase)"
                line(10, f"|     {pdisp[:dw-10]}".ljust(dw-1) + "|", field==4)
            else:
                line(10, "|".ljust(dw-1) + "|")
            
            line(11, "|" + "-"*(dw-2) + "|")
            line(12, "| LEFT/RIGHT:Change  SPACE:Toggle".ljust(dw-1) + "|")
            line(13, "| ENTER:Send  q:Cancel".ljust(dw-1) + "|")
            line(14, "+" + "-"*(dw-2) + "+")
            
            scr.refresh()
            
            # Get input
            try:
                key = scr.getch()
            except:
                continue
            
            debug(f"options: key={key} field={field}")
            
            # Handle keys
            if key in (ord('q'), ord('Q'), 27):  # q, Q, ESC
                opts.confirmed = False
                state["done"] = True
            
            elif key == curses.KEY_UP or key == ord('k'):
                state["field"] = max(0, field - 1)
                # Skip disabled fields
                if state["field"] == 4 and not opts.use_passphrase:
                    state["field"] = 3
                if state["field"] == 1 and opts.one_time:
                    state["field"] = 0
            
            elif key == curses.KEY_DOWN or key == ord('j'):
                state["field"] = min(4, field + 1)
                # Skip disabled fields
                if state["field"] == 1 and opts.one_time:
                    state["field"] = 2
                if state["field"] == 4 and not opts.use_passphrase:
                    state["field"] = 3
            
            elif key == curses.KEY_LEFT or key == ord('h'):
                if field == 0:
                    opts.expiry_idx = max(0, opts.expiry_idx - 1)
                elif field == 1 and not opts.one_time:
                    opts.max_downloads = max(1, opts.max_downloads - 1)
            
            elif key == curses.KEY_RIGHT or key == ord('l'):
                if field == 0:
                    opts.expiry_idx = min(len(EXPIRY_OPTIONS) - 1, opts.expiry_idx + 1)
                elif field == 1 and not opts.one_time:
                    opts.max_downloads = min(1000, opts.max_downloads + 1)
            
            elif key == ord(' '):  # Space for toggles
                if field == 2:
                    opts.one_time = not opts.one_time
                    if opts.one_time:
                        opts.max_downloads = 1
                elif field == 3:
                    opts.use_passphrase = not opts.use_passphrase
                    if not opts.use_passphrase:
                        opts.passphrase = ""
            
            elif field == 4 and opts.use_passphrase:
                # Passphrase text input
                if key in (curses.KEY_BACKSPACE, 127, 8):
                    opts.passphrase = opts.passphrase[:-1]
                elif 32 <= key <= 126:
                    opts.passphrase += chr(key)
            
            elif key in (10, 13, curses.KEY_ENTER):  # Enter
                # Validate passphrase if enabled
                if opts.use_passphrase and len(opts.passphrase) < 6:
                    continue  # Don't accept, passphrase too short
                opts.confirmed = True
                state["done"] = True
    
    # If stdscr provided (from ping), use it directly
    if stdscr is not None:
        run_dialog(stdscr)
    else:
        # Standalone mode
        try:
            curses.wrapper(run_dialog)
        except Exception as e:
            debug(f"options exception: {e}")
    
    return opts if opts.confirmed else None


# =============================================================================
# API Client
# =============================================================================

async def upload_file(server: str, data: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Upload encrypted blob. Returns (url, error)."""
    try:
        async with aiohttp.ClientSession(connector=_get_tcp_connector()) as s:
            async with s.post(
                f"{server.rstrip('/')}/api/upload",
                data=data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=aiohttp.ClientTimeout(total=120),
            ) as r:
                if r.status != 200:
                    return None, f"Upload failed: {r.status}"
                return (await r.json()).get("url"), None
    except Exception as e:
        return None, str(e)


async def create_link(server: str, file_url: str, expires_sec: int, max_dl: int, hard_delete: bool) -> Tuple[Optional[str], Optional[str]]:
    """Create share link. Returns (url, error)."""
    try:
        async with aiohttp.ClientSession(connector=_get_tcp_connector()) as s:
            async with s.post(
                f"{server.rstrip('/')}/api/links",
                json={"fileUrl": file_url, "expiresInSeconds": expires_sec, "maxDownloads": max_dl, "hardDelete": hard_delete},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as r:
                if r.status not in (200, 201):
                    return None, f"Link failed: {r.status}"
                return (await r.json()).get("url"), None
    except Exception as e:
        return None, str(e)


# =============================================================================
# Main Send Logic
# =============================================================================

async def send_file(filepath: Path, opts: ShareOptions, config: Config, log: Callable[[str], None]) -> Tuple[Optional[str], Optional[str]]:
    """Encrypt, upload, and create share link. Returns (share_hash, error)."""
    
    log("Reading file...")
    try:
        plaintext = filepath.read_bytes()
    except Exception as e:
        return None, f"Read error: {e}"
    
    log("Encrypting...")
    checksum = sha256_b64url(plaintext)
    enc = encrypt_aes_gcm(plaintext, opts.passphrase if opts.use_passphrase else None)
    
    log("Uploading...")
    file_url, err = await upload_file(config.server_url, enc["ciphertext"])
    if err: return None, err
    
    log("Creating link...")
    _, _, expires_sec = EXPIRY_OPTIONS[opts.expiry_idx]
    link_url, err = await create_link(config.server_url, file_url, expires_sec, opts.max_downloads, opts.one_time)
    if err: return None, err
    
    # Build share hash (matches Manuscrypt format exactly)
    payload = {
        "v": 2,
        "alg": "AES-GCM",
        "url": link_url,
        "iv": b64url_encode(enc["iv"]),
        "checksum": checksum,
        "ext": filepath.suffix.lstrip('.').lower() or "bin",
    }
    if opts.use_passphrase:
        payload["kdf"] = enc["kdf"]
    else:
        payload["key"] = b64url_encode(enc["key"])
    
    return build_share_hash(payload), None


# =============================================================================
# Addon
# =============================================================================

class SendAddon(PingAddon):
    name = "Send"
    version = "1.1.0"
    description = "Send files and shorten URLs via Manuscrypt"
    
    def __init__(self):
        super().__init__()
        self.config = Config.load()
        self.commands = {
            "send": (self.cmd_send, "Send file: /send [path]"),
            "shorten": (self.cmd_shorten, "Shorten URL: /shorten <url> [expiry]"),
        }
    
    def _restore_ping_ui(self):
        """Restore ping's curses UI after our dialogs."""
        try:
            from __main__ import CURSES_UI
            if CURSES_UI and CURSES_UI.stdscr:
                stdscr = CURSES_UI.stdscr
                
                # Reset colors first
                curses.start_color()
                curses.use_default_colors()
                try:
                    curses.init_pair(1, -1, -1)
                except:
                    pass
                
                stdscr.clear()
                stdscr.attrset(0)  # Reset all attributes
                CURSES_UI._create_windows()
                CURSES_UI._redraw_messages()
                CURSES_UI._draw_panel()
                CURSES_UI._draw_input()
                curses.doupdate()
                return True
        except Exception as e:
            debug(f"restore_ping_ui error: {e}")
        return False
    
    def _get_ping_stdscr(self):
        """Get ping's stdscr if available."""
        try:
            from __main__ import CURSES_UI
            if CURSES_UI and CURSES_UI.stdscr:
                return CURSES_UI.stdscr
        except:
            pass
        return None
    
    async def cmd_send(self, args: str, cli) -> None:
        args = args.strip()
        
        debug(f"cmd_send called with args: '{args}'")
        
        # Check deps
        if not HAS_CRYPTO:
            cli._print("  ✗ pip install cryptography")
            return
        if not HAS_AIOHTTP:
            cli._print("  ✗ pip install aiohttp")
            return
        
        # Config command
        if args == "config":
            cli._print(f"")
            cli._print(f"  Current server: {self.config.server_url}")
            cli._print(f"")
            cli._print(f"  To change, use: /send config <url>")
            cli._print(f"  Example: /send config https://manuscrypt.example.com")
            return
        
        # Config with URL argument
        if args.startswith("config "):
            url = args[7:].strip()
            if not url.startswith(("http://", "https://")):
                cli._print("  ✗ URL must start with http:// or https://")
                return
            self.config.server_url = url.rstrip('/')
            self.config.save()
            cli._print(f"  ✓ Server set to: {self.config.server_url}")
            return
        
        # Debug mode toggle
        if args == "debug":
            global DEBUG
            DEBUG = not DEBUG
            cli._print(f"  Debug mode: {'ON' if DEBUG else 'OFF'}")
            return
        
        # Must be in room
        if not cli.current_room:
            cli._print("  ✗ Join a room first")
            return
        
        # Get ping's stdscr for curses integration
        stdscr = self._get_ping_stdscr()
        
        # Get file
        filepath = None
        if args:
            p = Path(args).expanduser()
            if p.is_file(): 
                filepath = p
                debug(f"Using file from args: {filepath}")
            elif p.is_dir(): 
                debug(f"Opening browser in dir: {p}")
                if stdscr:
                    filepath = browse_files(p, stdscr)
                    self._restore_ping_ui()
                else:
                    filepath = browse_files(p)
            else:
                cli._print(f"  ✗ Not found: {args}")
                return
        else:
            if not HAS_CURSES:
                cli._print("  ✗ Provide path: /send <file>")
                return
            debug("Opening file browser")
            if stdscr:
                filepath = browse_files(stdscr=stdscr)
                self._restore_ping_ui()
            else:
                filepath = browse_files()
        
        if not filepath:
            cli._print("  Cancelled")
            return
        
        debug(f"Selected file: {filepath}")
        
        # Check size
        try:
            size = filepath.stat().st_size
        except Exception as e:
            cli._print(f"  ✗ {e}")
            return
        
        if size > MAX_FILE_SIZE:
            cli._print(f"  ✗ Too large: {format_size(size)} (max {format_size(MAX_FILE_SIZE)})")
            return
        if size == 0:
            cli._print("  ✗ Empty file")
            return
        
        # Options
        debug("Opening options dialog")
        if HAS_CURSES:
            if stdscr:
                opts = options_dialog(filepath.name, size, stdscr)
                self._restore_ping_ui()
            else:
                opts = options_dialog(filepath.name, size)
        else:
            opts = ShareOptions(confirmed=True)
        
        debug(f"Options result: {opts}")
        
        if not opts or not opts.confirmed:
            cli._print("  Cancelled")
            return
        
        # Send
        cli._print(f"  📤 Sending {filepath.name}...")
        share_hash, err = await send_file(filepath, opts, self.config, lambda m: cli._print(f"  {m}"))
        
        if err:
            cli._print(f"  ✗ {err}")
            return
        
        # Show success with expiry info
        _, exp_label, _ = EXPIRY_OPTIONS[opts.expiry_idx]
        lock = "🔒 " if opts.use_passphrase else ""
        cli._print(f"  ✓ Uploaded! (expires {exp_label})")
        
        # Build the full shareable URL
        share_url = f"{self.config.server_url}/?share={share_hash}"
        
        # Show the raw hash for reference
        cli._print(f"  ")
        cli._print(f"  Hash: {share_hash[:60]}...")
        
        # Shorten the share URL
        cli._print(f"  Creating short link...")
        try:
            async with aiohttp.ClientSession(connector=_get_tcp_connector()) as session:
                async with session.post(
                    f"{self.config.server_url.rstrip('/')}/api/shorten",
                    json={
                        "targetUrl": share_url,
                        "expiresInSeconds": EXPIRY_OPTIONS[opts.expiry_idx][2],
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        short_url = data.get("shortUrl")
                        if short_url:
                            cli._print(f"  ")
                            cli._print(f"  {short_url}")
                            cli._print(f"  ")
                            
                            # Send short URL to chat
                            try:
                                msg = f"{lock}📎 {filepath.name}"
                                await cli.client.send_message(msg)
                                msg = f"{short_url}"
                                await cli.client.send_message(msg)
                                cli._print(f"  ✓ Sent to chat!")
                                return
                            except Exception as e:
                                cli._print(f"  ⚠ Chat send failed: {e}")
                                return
        except Exception as e:
            debug(f"Shorten failed: {e}")
        
        # Fallback: send full share URL if shortening failed
        cli._print(f"  ⚠ Shortener unavailable, using full URL")
        cli._print(f"  ")
        cli._print(f"  {share_url}")
        cli._print(f"  ")
        
        # Send to chat
        try:
            msg = f"{lock}📎 {filepath.name} | {share_url}"
            await cli.client.send_message(msg)
            cli._print(f"  ✓ Sent to chat!")
        except Exception as e:
            cli._print(f"  ⚠ Chat send failed: {e}")
            cli._print(f"  (URL shown above - copy manually)")
    
    async def cmd_shorten(self, args: str, cli) -> None:
        """Handle /shorten command - create short URLs via Manuscrypt."""
        args = args.strip()
        
        # Check deps
        if not HAS_AIOHTTP:
            cli._print("  ✗ pip install aiohttp")
            return
        
        # Parse arguments: /shorten <url> [expiry] [password]
        # Expiry can be: 1h, 1d, 7d, 21d (default: 7d)
        if not args:
            cli._print("  Usage: /shorten <url> [expiry] [password]")
            cli._print("  ")
            cli._print("  Expiry: 1h, 1d, 7d (default), 21d")
            cli._print("  ")
            cli._print("  Examples:")
            cli._print("    /shorten https://example.com/path")
            cli._print("    /shorten https://example.com 1d")
            cli._print("    /shorten https://example.com 7d secretpass")
            return
        
        parts = args.split()
        url = parts[0]
        
        # Validate URL
        if not url.startswith(("http://", "https://")):
            cli._print("  ✗ URL must start with http:// or https://")
            return
        
        # Parse expiry (default 7d)
        expiry_code = "7d"
        password = None
        
        if len(parts) > 1:
            # Check if second arg is expiry or password
            if parts[1] in ("1h", "1d", "7d", "21d"):
                expiry_code = parts[1]
                if len(parts) > 2:
                    password = parts[2]
            else:
                # Assume it's a password
                password = parts[1]
        
        # Get expiry seconds
        expiry_idx = 2  # Default to 7d
        for i, (code, _, _) in enumerate(EXPIRY_OPTIONS):
            if code == expiry_code:
                expiry_idx = i
                break
        
        _, expiry_label, expiry_seconds = EXPIRY_OPTIONS[expiry_idx]
        
        cli._print(f"  🔗 Creating short URL...")
        
        # Call the dedicated shorten API
        try:
            async with aiohttp.ClientSession(connector=_get_tcp_connector()) as session:
                payload = {
                    "targetUrl": url,
                    "expiresInSeconds": expiry_seconds,
                }
                if password:
                    payload["password"] = password
                
                async with session.post(
                    f"{self.config.server_url.rstrip('/')}/api/shorten",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status not in (200, 201):
                        err_data = await resp.json()
                        cli._print(f"  ✗ {err_data.get('error', f'HTTP {resp.status}')}")
                        return
                    
                    data = await resp.json()
                    short_url = data.get("shortUrl")
                    
                    if not short_url:
                        cli._print("  ✗ No short URL returned")
                        return
                    
                    lock = "🔒 " if password else ""
                    cli._print(f"  ✓ Created! (expires {expiry_label})")
                    cli._print(f"  ")
                    cli._print(f"  {lock}{short_url}")
                    cli._print(f"  ")
                    
                    # Send to chat if in a room
                    if cli.current_room:
                        try:
                            await cli.client.send_message(f"{lock}🔗 {short_url}")
                            cli._print(f"  ✓ Sent to chat!")
                        except Exception as e:
                            cli._print(f"  ⚠ Chat send failed: {e}")
        
        except Exception as e:
            cli._print(f"  ✗ Error: {e}")


def setup() -> SendAddon:
    return SendAddon()


# =============================================================================
# Standalone Mode
# =============================================================================

async def standalone_send(filepath: Path, server_url: str, opts: ShareOptions) -> None:
    """Standalone file send - no ping integration."""
    print(f"  📤 Sending {filepath.name}...")
    
    config = Config(server_url=server_url)
    
    def log(msg):
        print(f"  {msg}")
    
    share_hash, err = await send_file(filepath, opts, config, log)
    
    if err:
        print(f"  ✗ {err}")
        return
    
    _, exp_label, exp_seconds = EXPIRY_OPTIONS[opts.expiry_idx]
    lock = "🔒 " if opts.use_passphrase else ""
    print(f"  ✓ Uploaded! (expires {exp_label})")
    
    # Build the full shareable URL
    share_url = f"{server_url}/?share={share_hash}"
    
    print(f"  ")
    print(f"  Hash: {share_hash[:70]}...")
    
    # Try to shorten
    print(f"  Creating short link...")
    try:
        async with aiohttp.ClientSession(connector=_get_tcp_connector()) as session:
            async with session.post(
                f"{server_url.rstrip('/')}/api/shorten",
                json={"targetUrl": share_url, "expiresInSeconds": exp_seconds},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status in (200, 201):
                    data = await resp.json()
                    short_url = data.get("shortUrl")
                    if short_url:
                        print(f"  ")
                        print(f"  {lock}{short_url}")
                        print(f"  ")
                        return
    except Exception as e:
        pass
    
    # Fallback to full URL
    print(f"  ")
    print(f"  {lock}{share_url}")
    print(f"  ")


async def standalone_shorten(url: str, server_url: str, expiry_code: str = "7d", password: str = None) -> None:
    """Standalone URL shortening."""
    print(f"  🔗 Creating short URL...")
    
    # Get expiry seconds
    expiry_seconds = 604800  # Default 7d
    expiry_label = "7 days"
    for code, label, seconds in EXPIRY_OPTIONS:
        if code == expiry_code:
            expiry_seconds = seconds
            expiry_label = label
            break
    
    try:
        async with aiohttp.ClientSession(connector=_get_tcp_connector()) as session:
            payload = {"targetUrl": url, "expiresInSeconds": expiry_seconds}
            if password:
                payload["password"] = password
            
            async with session.post(
                f"{server_url.rstrip('/')}/api/shorten",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status not in (200, 201):
                    err_data = await resp.json()
                    print(f"  ✗ {err_data.get('error', f'HTTP {resp.status}')}")
                    return
                
                data = await resp.json()
                short_url = data.get("shortUrl")
                
                if short_url:
                    lock = "🔒 " if password else ""
                    print(f"  ✓ Created! (expires {expiry_label})")
                    print(f"  ")
                    print(f"  {lock}{short_url}")
                    print(f"  ")
                else:
                    print(f"  ✗ No short URL returned")
    
    except Exception as e:
        print(f"  ✗ Error: {e}")


def run_standalone():
    """Run in standalone mode with full functionality."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Manuscrypt - Encrypted file sharing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s send ~/document.pdf
  %(prog)s send -e 1d ~/photo.jpg
  %(prog)s send -p mypassword ~/secret.txt
  %(prog)s shorten https://example.com/long/url
  %(prog)s shorten -e 1h https://example.com/temp
  %(prog)s shorten -p secret https://private.link
        """
    )
    
    parser.add_argument("-s", "--server", default=DEFAULT_SERVER,
                        help=f"Manuscrypt server URL (default: {DEFAULT_SERVER})")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug output")
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # Send command
    send_parser = subparsers.add_parser("send", help="Send encrypted file")
    send_parser.add_argument("file", type=Path, nargs="?",
                             help="File to send (opens browser if not specified)")
    send_parser.add_argument("-e", "--expiry", choices=["1h", "1d", "7d", "21d"], default="7d",
                             help="Link expiry (default: 7d)")
    send_parser.add_argument("-p", "--password", 
                             help="Passphrase protection")
    send_parser.add_argument("-1", "--one-time", action="store_true",
                             help="One-time link (deleted after first access)")
    send_parser.add_argument("-m", "--max-downloads", type=int, default=5,
                             help="Max downloads (default: 5)")
    
    # Shorten command
    shorten_parser = subparsers.add_parser("shorten", help="Shorten URL")
    shorten_parser.add_argument("url", help="URL to shorten")
    shorten_parser.add_argument("-e", "--expiry", choices=["1h", "1d", "7d", "21d"], default="7d",
                                help="Link expiry (default: 7d)")
    shorten_parser.add_argument("-p", "--password",
                                help="Password protection")
    
    # Test command
    test_parser = subparsers.add_parser("test", help="Run crypto tests")
    
    args = parser.parse_args()
    
    if args.debug:
        global DEBUG
        DEBUG = True
    
    # No command - show help
    if not args.command:
        parser.print_help()
        return
    
    # Test command
    if args.command == "test":
        print("Manuscrypt - Crypto Test")
        print("=" * 40)
        
        print(f"{'✓' if HAS_CRYPTO else '✗'} cryptography")
        print(f"{'✓' if HAS_AIOHTTP else '✗'} aiohttp")
        print(f"{'✓' if HAS_CURSES else '✗'} curses")
        
        if not HAS_CRYPTO:
            print("\n✗ pip install cryptography aiohttp")
            return
        
        print("\nTesting encryption...")
        data = b"Hello Manuscrypt!"
        enc = encrypt_aes_gcm(data)
        dec = AESGCM(enc["key"]).decrypt(enc["iv"], enc["ciphertext"], None)
        assert dec == data
        print("✓ AES-256-GCM encryption OK")
        
        print("\nTesting passphrase encryption...")
        enc2 = encrypt_aes_gcm(data, "testpassword")
        assert enc2["kdf"] is not None
        assert enc2["kdf"]["iterations"] == 200000
        print("✓ PBKDF2 key derivation OK")
        
        print("\nTesting share hash...")
        payload = {
            "v": 2, "alg": "AES-GCM", "url": "https://test",
            "iv": b64url_encode(enc["iv"]),
            "checksum": sha256_b64url(data),
            "ext": "txt",
            "key": b64url_encode(enc["key"])
        }
        h = build_share_hash(payload)
        assert h.startswith("manuscrypt:")
        print(f"✓ Share hash: {h[:50]}...")
        
        print("\n✓ All tests passed!")
        return
    
    # Check dependencies for send/shorten
    if not HAS_CRYPTO:
        print("✗ Missing: pip install cryptography")
        return
    if not HAS_AIOHTTP:
        print("✗ Missing: pip install aiohttp")
        return
    
    # Send command
    if args.command == "send":
        filepath = args.file
        
        # File browser if no file specified
        if not filepath:
            if not HAS_CURSES:
                print("✗ No file specified and curses not available")
                return
            print("Opening file browser...")
            filepath = browse_files()
            # Reset terminal
            try:
                os.system('stty sane 2>/dev/null')
            except:
                pass
            
            if not filepath:
                print("Cancelled")
                return
        
        # Validate file
        filepath = filepath.expanduser()
        if not filepath.is_file():
            print(f"✗ Not found: {filepath}")
            return
        
        size = filepath.stat().st_size
        if size > MAX_FILE_SIZE:
            print(f"✗ Too large: {format_size(size)} (max {format_size(MAX_FILE_SIZE)})")
            return
        if size == 0:
            print("✗ Empty file")
            return
        
        # Build options
        expiry_idx = 2  # Default 7d
        for i, (code, _, _) in enumerate(EXPIRY_OPTIONS):
            if code == args.expiry:
                expiry_idx = i
                break
        
        opts = ShareOptions(
            expiry_idx=expiry_idx,
            max_downloads=1 if args.one_time else args.max_downloads,
            one_time=args.one_time,
            use_passphrase=bool(args.password),
            passphrase=args.password or "",
            confirmed=True
        )
        
        # Run async send
        asyncio.run(standalone_send(filepath, args.server, opts))
        return
    
    # Shorten command
    if args.command == "shorten":
        if not args.url.startswith(("http://", "https://")):
            print("✗ URL must start with http:// or https://")
            return
        
        asyncio.run(standalone_shorten(args.url, args.server, args.expiry, args.password))
        return


if __name__ == "__main__":
    run_standalone()
