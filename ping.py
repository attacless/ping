#!/usr/bin/env python3
"""
Ping - Encrypted P2P Messenger

Uses the Nostr protocol for decentralized message relay.
Connects to multiple public relays for redundancy.

Protocol:
- NIP-01: Basic protocol
- NIP-04: Encrypted Direct Messages (we use our own E2E encryption on top)
- Custom kind for Ping rooms

Cryptographic Stack:
- X25519 ECDH for key exchange
- ChaCha20-Poly1305 for message encryption
- secp256k1 for Nostr identity
"""

import asyncio
import json
import hashlib
import hmac
import secrets
import struct
import time
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List, Tuple, Callable
from enum import IntEnum

# Cryptography
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print("Install: pip install cryptography")
    sys.exit(1)

# WebSocket
try:
    import websockets
    import ssl
    import certifi
    WEBSOCKETS_VERSION = tuple(int(x) for x in websockets.__version__.split('.')[:2])
    # Create SSL context with certifi certificates (fixes Mac issue)
    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    try:
        import websockets
        import ssl
        WEBSOCKETS_VERSION = tuple(int(x) for x in websockets.__version__.split('.')[:2])
        SSL_CONTEXT = ssl.create_default_context()
    except ImportError:
        print("Install: pip install websockets certifi")
        sys.exit(1)

# secp256k1 for Nostr signatures - try multiple options
SECP256K1_LIB = None

# Option 1: secp256k1 (fastest, has native Schnorr)
try:
    from secp256k1 import PrivateKey as Secp256k1PrivateKey
    SECP256K1_LIB = "secp256k1"
except ImportError:
    pass

# Option 2: coincurve (need to implement Schnorr manually)
if not SECP256K1_LIB:
    try:
        from coincurve import PrivateKey as CoincurvePrivateKey
        from coincurve import PublicKey as CoincurvePublicKey
        SECP256K1_LIB = "coincurve"
    except ImportError:
        pass

# Option 3: Pure Python fallback (slowest but always works)
if not SECP256K1_LIB:
    SECP256K1_LIB = "pure_python"

# Will print in main() if DEBUG is set


# ==============================================================================
# BIP-340 Schnorr Signatures (Pure Python Implementation)
# ==============================================================================

# secp256k1 curve parameters
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)

def _modinv(a: int, m: int) -> int:
    """Modular inverse using extended Euclidean algorithm"""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse doesn't exist")
    return x % m

def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def _point_add(p1, p2):
    """Add two points on secp256k1"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    if x1 == x2 and y1 != y2:
        return None
    
    if x1 == x2:
        # Point doubling
        m = (3 * x1 * x1 * _modinv(2 * y1, SECP256K1_P)) % SECP256K1_P
    else:
        m = ((y2 - y1) * _modinv(x2 - x1, SECP256K1_P)) % SECP256K1_P
    
    x3 = (m * m - x1 - x2) % SECP256K1_P
    y3 = (m * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)

def _point_mul(k: int, point=None):
    """Multiply a point by a scalar"""
    if point is None:
        point = SECP256K1_G
    
    result = None
    addend = point
    
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    
    return result

def _bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, 'big')

def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP-340 tagged hash"""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def _lift_x(x: int):
    """Lift x coordinate to a point (BIP-340)"""
    if x >= SECP256K1_P:
        return None
    y_sq = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(y, 2, SECP256K1_P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else SECP256K1_P - y)

def _has_even_y(point) -> bool:
    return point[1] % 2 == 0

def schnorr_sign(msg: bytes, seckey: bytes) -> bytes:
    """BIP-340 Schnorr signature"""
    if len(msg) != 32:
        raise ValueError("Message must be 32 bytes")
    if len(seckey) != 32:
        raise ValueError("Secret key must be 32 bytes")
    
    d = _int_from_bytes(seckey)
    if d == 0 or d >= SECP256K1_N:
        raise ValueError("Invalid secret key")
    
    P = _point_mul(d)
    if not _has_even_y(P):
        d = SECP256K1_N - d
    
    # BIP-340 aux rand (we use zeros for deterministic signatures)
    aux = bytes(32)
    t = _int_from_bytes(seckey) ^ _int_from_bytes(_tagged_hash("BIP0340/aux", aux))
    
    k0 = _int_from_bytes(_tagged_hash("BIP0340/nonce", _bytes_from_int(t) + _bytes_from_int(P[0]) + msg)) % SECP256K1_N
    if k0 == 0:
        raise ValueError("Failure. This happens only with negligible probability.")
    
    R = _point_mul(k0)
    k = k0 if _has_even_y(R) else SECP256K1_N - k0
    
    e = _int_from_bytes(_tagged_hash("BIP0340/challenge", _bytes_from_int(R[0]) + _bytes_from_int(P[0]) + msg)) % SECP256K1_N
    
    sig = _bytes_from_int(R[0]) + _bytes_from_int((k + e * d) % SECP256K1_N)
    return sig

def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    """Verify BIP-340 Schnorr signature"""
    if len(msg) != 32 or len(pubkey) != 32 or len(sig) != 64:
        return False
    
    P = _lift_x(_int_from_bytes(pubkey))
    if P is None:
        return False
    
    r = _int_from_bytes(sig[:32])
    s = _int_from_bytes(sig[32:])
    
    if r >= SECP256K1_P or s >= SECP256K1_N:
        return False
    
    e = _int_from_bytes(_tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg)) % SECP256K1_N
    
    R = _point_add(_point_mul(s), _point_mul(SECP256K1_N - e, P))
    
    if R is None or not _has_even_y(R) or R[0] != r:
        return False
    
    return True


# ==============================================================================
# Constants
# ==============================================================================
APP_VERSION = "1.1.46"
APP_ID = "ping-e2e-v1"
DEBUG = False  # Set via --debug flag
LEGACY_MODE = False  # Legacy mode for old client compatibility (--legacy)
HARDENED_MODE = False  # Hardened mode with all features (--hardened)
SOUND_ENABLED = True  # Sound notifications (--no-sound to disable)
CURRENT_THEME = None  # Current theme name (if using a theme)
CURRENT_BG = None  # Current background color
CURRENT_FG = None  # Current foreground color

# Auto-update settings
# Repository must be public for auto-update to work
UPDATE_URL = "https://raw.githubusercontent.com/attacless/ping/main/ping.py"
UPDATE_CHECK_URL = UPDATE_URL  # Same URL, we'll check version from content

# Public Nostr relays (decentralized!) - free, no signup required
# NOSTR_RELAYS = [
#     "wss://relay.damus.io",
#     "wss://nos.lol",
#     "wss://relay.snort.social",
#     "wss://nostr.mom",
#     "wss://relay.primal.net",
# ]

NOSTR_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.snort.social",
    "wss://nostr.mom",
    "wss://relay.primal.net",
    "wss://offchain.pub",
    "wss://soloco.nl",
    "wss://nostr.oxtr.dev",
]


# Nostr event kinds
class NostrKind(IntEnum):
    METADATA = 0
    TEXT_NOTE = 1
    RECOMMEND_RELAY = 2
    CONTACTS = 3
    ENCRYPTED_DM = 4
    DELETE = 5
    REPOST = 6
    REACTION = 7
    # Custom kinds for Ping (regular kinds for better relay support)
    PING_ROOM_MESSAGE = 4242      # Encrypted room message
    PING_KEY_EXCHANGE = 4243      # Key exchange
    PING_PRESENCE = 4244          # Presence announcement
    PING_LEAVE = 4245             # Disconnect announcement
    PING_DM = 4246                # Direct message (peer-to-peer)

# Privacy Shield envelope types (hidden inside encrypted envelope)
class EnvelopeType(IntEnum):
    MESSAGE = 1
    KEY_EXCHANGE = 2
    PRESENCE = 3
    LEAVE = 4
    DM = 5
    DECOY = 255  # Fake traffic

# Privacy Shield Configuration
@dataclass
class PrivacyConfig:
    """Phase 3 Privacy Shield configuration"""
    # Encrypted envelope - encrypt ALL metadata
    envelope_enabled: bool = True
    
    # Ephemeral pubkeys - rotate Nostr identity  
    ephemeral_pubkeys: bool = True
    rotate_pubkey_interval: int = 3600  # Seconds (1 hour)
    rotate_pubkey_per_room: bool = True
    
    # === HARDENED MODE FEATURES (--hardened) ===
    # Room tag obfuscation - can interfere with peer discovery
    room_obfuscation: bool = False
    decoy_room_count: int = 5
    room_alias_rotation: int = 1800  # 30 min
    
    # Timing protection - can interfere with real-time chat
    timing_jitter: bool = False
    min_delay_ms: int = 50
    max_delay_ms: int = 300
    timestamp_quantization: int = 60  # Round to N seconds
    
    # Decoy traffic - adds bandwidth overhead
    decoy_traffic: bool = False
    decoy_min_interval: int = 15
    decoy_max_interval: int = 45
    # === END HARDENED MODE FEATURES ===
    
    # Enhanced padding buckets
    padding_buckets: list = field(default_factory=lambda: [512, 1024, 2048, 4096])
    
    # Use generic event kind to blend with normal traffic
    use_generic_kind: bool = True
    generic_kind: int = 4  # NIP-04 encrypted DM
    
    @staticmethod
    def default() -> 'PrivacyConfig':
        """Default privacy config (envelopes + ephemeral keys + generic kind)"""
        return PrivacyConfig(
            envelope_enabled=True,
            ephemeral_pubkeys=True,
            use_generic_kind=True,
        )
    
    @staticmethod
    def hardened() -> 'PrivacyConfig':
        """Hardened mode: full protection (all features)"""
        return PrivacyConfig(
            envelope_enabled=True,
            ephemeral_pubkeys=True,
            room_obfuscation=True,
            timing_jitter=True,
            decoy_traffic=True,
            use_generic_kind=True,
        )
    
    @staticmethod
    def legacy() -> 'PrivacyConfig':
        """Legacy mode (no privacy features, compatible with old clients)"""
        return PrivacyConfig(
            envelope_enabled=False,
            ephemeral_pubkeys=False,
            room_obfuscation=False,
            timing_jitter=False,
            decoy_traffic=False,
            use_generic_kind=False,
        )

# Crypto
HKDF_INFO = b"ping-nostr-chacha20poly1305-v1"
PADDING_BUCKETS = [256, 512, 1024, 2048, 4096, 8192]

# Storage - determine writable data directory
def get_data_dir() -> Path:
    """Get writable data directory, with fallback to script directory"""
    # Primary: ~/.ping
    primary = Path.home() / ".ping"
    
    # Fallback: script directory / .ping-data
    script_dir = Path(__file__).parent.resolve()
    fallback = script_dir / ".ping-data"
    
    # Check if primary is usable
    try:
        primary.mkdir(parents=True, exist_ok=True)
        # Test write access
        test_file = primary / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
        return primary
    except (OSError, PermissionError, IOError):
        pass
    
    # Try fallback (script directory)
    try:
        fallback.mkdir(parents=True, exist_ok=True)
        test_file = fallback / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
        return fallback
    except (OSError, PermissionError, IOError):
        pass
    
    # Last resort: current working directory
    cwd_fallback = Path.cwd() / ".ping-data"
    try:
        cwd_fallback.mkdir(parents=True, exist_ok=True)
        return cwd_fallback
    except (OSError, PermissionError, IOError):
        # Give up, return primary and let it fail later with proper error
        return primary

DATA_DIR = get_data_dir()

# Usernames
ADJECTIVES = ["cosmic", "quantum", "stellar", "cyber", "neon", "shadow", "phantom", "mystic",
              "swift", "silent", "stealth", "ghost", "brave", "fierce", "dark", "bright",
              "electric", "lunar", "solar", "void", "crystal", "thunder", "frost", "ember"]
NOUNS = ["wolf", "hawk", "eagle", "tiger", "dragon", "phoenix", "raven", "cobra",
         "knight", "samurai", "coder", "hacker", "cipher", "node", "star", "nova",
         "storm", "blade", "spark", "pulse", "wave", "byte", "pixel", "vector"]

# Terminal Colors (ANSI escape codes)
# Foreground colors (30-37 normal, 90-97 bright/light)
# Background colors (40-47 normal, 100-107 bright/light)
COLORS = {
    # Normal colors
    "black":    (30, 40),
    "red":      (31, 41),
    "green":    (32, 42),
    "yellow":   (33, 43),
    "blue":     (34, 44),
    "magenta":  (35, 45),
    "cyan":     (36, 46),
    "white":    (37, 47),
    # Light/bright colors
    "lblack":   (90, 100),   # Gray
    "gray":     (90, 100),
    "grey":     (90, 100),
    "lred":     (91, 101),
    "lgreen":   (92, 102),
    "lyellow":  (93, 103),
    "lblue":    (94, 104),
    "lmagenta": (95, 105),
    "lcyan":    (96, 106),
    "lwhite":   (97, 107),
    # Brown (yellow appears brown on dark backgrounds)
    "brown":    (33, 43),    # Same as yellow
    "lbrown":   (93, 103),   # Same as lyellow (tan/beige)
    "tan":      (93, 103),   # Alias for lbrown
    "orange":   (93, 103),   # lyellow often looks orange-ish
    # Aliases
    "default":  (39, 49),    # Reset to terminal default
    "none":     (39, 49),
    "reset":    (0, 0),
}

# Color Themes (bg, fg)
THEMES = {
    "matrix":   ("black", "lgreen"),    # Classic Matrix / Hacker
    "hacker":   ("black", "lgreen"),    # Alias for matrix
    "neo":      ("black", "lgreen"),    # Alias for matrix
    "tron":     ("black", "cyan"),      # Tron style
    "cyber":    ("black", "cyan"),      # Alias for tron
    "classic":  ("blue", "white"),      # Classic terminal
    "ibm":      ("blue", "white"),      # Alias for classic
    "amber":    ("black", "lyellow"),   # Amber CRT monitor
    "crt":      ("black", "lyellow"),   # Alias for amber
    "retro":    ("black", "lyellow"),   # Alias for amber
    "light":    ("lblue", "black"),     # Light mode
    "day":      ("lblue", "black"),     # Alias for light
    "ocean":    ("blue", "lcyan"),      # Ocean vibes
    "sunset":   ("black", "lred"),      # Sunset / warm
    "fire":     ("black", "lred"),      # Alias for sunset
    "grape":    ("black", "lmagenta"),  # Purple theme
    "purple":   ("black", "lmagenta"),  # Alias for grape
    "snow":     ("white", "black"),     # High contrast light
    "midnight": ("black", "lblue"),     # Midnight blue
    "coffee":   ("black", "brown"),     # Coffee / sepia tone
    "sepia":    ("black", "brown"),     # Alias for coffee
    "earth":    ("black", "brown"),     # Alias for coffee
    "africa":   ("black", "black"),       # Pan-African colors
    "mumbai":   ("yellow", "red"),        # India colors
    "usa":      ("white", "red"),         # American colors
    "default":  (None, None),           # Terminal default
    "reset":    (None, None),           # Alias for default
}

def get_theme(name: str) -> tuple[Optional[str], Optional[str]]:
    """Get (bg, fg) colors for a theme name"""
    return THEMES.get(name.lower(), (None, None))

def set_terminal_color(bg: Optional[str] = None, fg: Optional[str] = None) -> str:
    """Generate ANSI escape sequence for terminal colors"""
    codes = []
    
    if fg and fg.lower() in COLORS:
        codes.append(str(COLORS[fg.lower()][0]))
    
    if bg and bg.lower() in COLORS:
        codes.append(str(COLORS[bg.lower()][1]))
    
    if codes:
        return f"\033[{';'.join(codes)}m"
    return ""

def reset_terminal_color() -> str:
    """Reset terminal to default colors"""
    return "\033[0m"

def apply_terminal_color(bg: Optional[str] = None, fg: Optional[str] = None):
    """Apply terminal colors immediately"""
    global CURRENT_BG, CURRENT_FG, CURRENT_THEME
    if bg or fg:
        print(set_terminal_color(bg, fg), end='', flush=True)
        CURRENT_BG = bg
        CURRENT_FG = fg
        CURRENT_THEME = None  # Custom colors, not a theme

def apply_theme(theme_name: str) -> bool:
    """Apply a named theme. Returns True if theme exists."""
    global CURRENT_BG, CURRENT_FG, CURRENT_THEME
    if theme_name.lower() in THEMES:
        bg, fg = THEMES[theme_name.lower()]
        if bg is None and fg is None:
            print(reset_terminal_color(), end='', flush=True)
            CURRENT_BG = None
            CURRENT_FG = None
            CURRENT_THEME = None
        else:
            apply_terminal_color(bg, fg)
            CURRENT_THEME = theme_name.lower()
        return True
    return False

def clear_screen_with_color():
    """Clear screen and fill with current background color"""
    import os
    # Clear screen
    print("\033[2J\033[H", end='', flush=True)


# ==============================================================================
# Sound Notifications
# ==============================================================================

def beep_message():
    """Play a beep sound for regular messages"""
    if not SOUND_ENABLED:
        return
    # Terminal bell
    print("\a", end='', flush=True)

def beep_dm():
    """Play a different sound for DMs (double beep)"""
    if not SOUND_ENABLED:
        return
    # Double beep for DMs
    print("\a", end='', flush=True)
    try:
        import time
        time.sleep(0.15)
        print("\a", end='', flush=True)
    except:
        pass

def beep_mention():
    """Play sound when mentioned (triple beep)"""
    if not SOUND_ENABLED:
        return
    # Triple beep for mentions
    try:
        import time
        for i in range(3):
            print("\a", end='', flush=True)
            if i < 2:
                time.sleep(0.1)
    except:
        print("\a", end='', flush=True)


# ==============================================================================
# Utilities
# ==============================================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def gen_username() -> str:
    return f"{secrets.choice(ADJECTIVES)}-{secrets.choice(NOUNS)}-{secrets.randbelow(900)+100}"

def gen_msg_id() -> str:
    return secrets.token_hex(16)

def bech32_charset():
    return "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_encode(hrp: str, data: bytes) -> str:
    """Simple bech32 encoding for npub/nsec display"""
    # Convert to 5-bit groups
    acc = 0
    bits = 0
    result = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            result.append((acc >> bits) & 31)
    if bits:
        result.append((acc << (5 - bits)) & 31)
    
    # Checksum (simplified - not full bech32m)
    charset = bech32_charset()
    return hrp + "1" + "".join(charset[d] for d in result)


# ==============================================================================
# Auto-Updater
# ==============================================================================

def extract_version(content: str) -> Optional[str]:
    """Extract APP_VERSION from script content"""
    import re
    match = re.search(r'APP_VERSION\s*=\s*["\']([^"\']+)["\']', content)
    if match:
        return match.group(1)
    return None

def compare_versions(current: str, remote: str) -> int:
    """Compare version strings. Returns: -1 if current < remote, 0 if equal, 1 if current > remote"""
    def parse_version(v: str) -> tuple:
        # Handle versions like "1.0.0", "1.0.0-beta", etc.
        parts = v.replace('-', '.').split('.')
        result = []
        for p in parts:
            try:
                result.append(int(p))
            except ValueError:
                result.append(p)
        return tuple(result)
    
    try:
        curr = parse_version(current)
        rem = parse_version(remote)
        if curr < rem:
            return -1
        elif curr > rem:
            return 1
        return 0
    except Exception:
        return 0

def fetch_remote_script() -> tuple[Optional[str], Optional[str]]:
    """Fetch the latest script from GitHub. Returns (content, error_message)"""
    import urllib.request
    import ssl
    
    errors = []
    
    # Method 1: Try with default SSL context
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            UPDATE_URL,
            headers={'User-Agent': f'PingNostr/{APP_VERSION}'}
        )
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            return response.read().decode('utf-8'), None
    except Exception as e:
        errors.append(f"SSL context: {e}")
    
    # Method 2: Try with certifi if available (helps on macOS/iOS)
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
        req = urllib.request.Request(
            UPDATE_URL,
            headers={'User-Agent': f'PingNostr/{APP_VERSION}'}
        )
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            return response.read().decode('utf-8'), None
    except ImportError:
        errors.append("certifi not installed")
    except Exception as e:
        errors.append(f"certifi: {e}")
    
    # Method 3: Try with unverified context (less secure, but works)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            UPDATE_URL,
            headers={'User-Agent': f'PingNostr/{APP_VERSION}'}
        )
        with urllib.request.urlopen(req, timeout=15, context=ctx) as response:
            return response.read().decode('utf-8'), None
    except Exception as e:
        errors.append(f"unverified: {e}")
    
    # All methods failed
    error_msg = "; ".join(errors)
    if DEBUG:
        print(f"    [debug] All fetch methods failed: {error_msg}")
    return None, error_msg

def check_for_updates() -> tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Check if updates are available. Returns (update_available, remote_version, remote_content, error)"""
    content, error = fetch_remote_script()
    if not content:
        return False, None, None, error
    
    remote_version = extract_version(content)
    if not remote_version:
        return False, None, None, "Could not parse version from remote script"
    
    if compare_versions(APP_VERSION, remote_version) < 0:
        return True, remote_version, content, None
    
    return False, remote_version, content, None

def get_script_path() -> Path:
    """Get the path to the current script"""
    return Path(__file__).resolve()

def perform_update(new_content: str) -> tuple[bool, str]:
    """
    Update the script file with new content.
    Returns (success, message)
    """
    script_path = get_script_path()
    backup_path = script_path.with_suffix('.py.backup')
    
    try:
        # Read current content for backup
        current_content = script_path.read_text(encoding='utf-8')
        
        # Create backup
        try:
            backup_path.write_text(current_content, encoding='utf-8')
        except Exception as e:
            # Continue without backup if it fails
            if DEBUG:
                print(f"    [debug] Backup failed: {e}")
        
        # Write new content
        script_path.write_text(new_content, encoding='utf-8')
        
        return True, f"Updated successfully! Backup saved to {backup_path.name}"
    
    except PermissionError:
        return False, "Permission denied. Try running with appropriate permissions."
    except Exception as e:
        return False, f"Update failed: {e}"

def restore_backup() -> tuple[bool, str]:
    """Restore from backup file"""
    script_path = get_script_path()
    backup_path = script_path.with_suffix('.py.backup')
    
    if not backup_path.exists():
        return False, "No backup file found"
    
    try:
        backup_content = backup_path.read_text(encoding='utf-8')
        script_path.write_text(backup_content, encoding='utf-8')
        return True, "Restored from backup successfully"
    except Exception as e:
        return False, f"Restore failed: {e}"


def cli_update() -> int:
    """
    Check for updates and apply them from command line.
    Returns exit code: 0=updated, 1=no update, 2=error
    """
    print(f"  Ping v{APP_VERSION}")
    print(f"  Checking for updates...")
    
    update_available, remote_version, content, error = check_for_updates()
    
    if error:
        print(f"  ✗ Error: {error}")
        return 2
    
    if not update_available:
        print(f"  ✓ Already up to date (v{remote_version})")
        return 1
    
    print(f"  ⬆ Update available: v{APP_VERSION} → v{remote_version}")
    print(f"  Installing update...")
    
    success, message = perform_update(content)
    
    if success:
        print(f"  ✓ {message}")
        
        # Prompt for restart
        try:
            response = input("  Restart now? [Y/n]: ").strip().lower()
            if response in ('', 'y', 'yes'):
                import os
                script_path = str(get_script_path())
                print(f"  Restarting...")
                os.execv(sys.executable, [sys.executable, script_path] + sys.argv[1:])
        except (KeyboardInterrupt, EOFError):
            pass
        
        print(f"  Run 'python {Path(__file__).name}' to use the new version")
        return 0
    else:
        print(f"  ✗ {message}")
        return 2


# ==============================================================================
# Invite System
# ==============================================================================

INVITE_PREFIX = "ping1"  # Bech32-like prefix for invites

def encode_invite(room: str, password: Optional[str] = None) -> str:
    """Encode room + password into a shareable invite code"""
    import base64
    
    # Create invite data
    invite_data = {"r": room}
    if password:
        invite_data["p"] = password
    
    # Encode as JSON, then base64url
    json_bytes = json.dumps(invite_data, separators=(',', ':')).encode()
    encoded = base64.urlsafe_b64encode(json_bytes).rstrip(b'=').decode()
    
    return f"{INVITE_PREFIX}{encoded}"

def decode_invite(invite_code: str) -> tuple[Optional[str], Optional[str]]:
    """Decode invite code into (room, password). Returns (None, None) if invalid."""
    import base64
    
    try:
        # Remove prefix
        if not invite_code.startswith(INVITE_PREFIX):
            return None, None
        
        encoded = invite_code[len(INVITE_PREFIX):]
        
        # Add padding back
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding
        
        # Decode
        json_bytes = base64.urlsafe_b64decode(encoded)
        invite_data = json.loads(json_bytes)
        
        room = invite_data.get("r")
        password = invite_data.get("p")
        
        return room, password
    except Exception:
        return None, None

def generate_qr_code(data: str, small: bool = False) -> str:
    """Generate ASCII QR code. Returns empty string if qrcode not installed."""
    try:
        import qrcode
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Generate ASCII art
        modules = qr.get_matrix()
        
        if small:
            # Use half-block characters for compact display
            lines = []
            for y in range(0, len(modules), 2):
                line = "  "
                for x in range(len(modules[0])):
                    top = modules[y][x] if y < len(modules) else False
                    bottom = modules[y + 1][x] if y + 1 < len(modules) else False
                    
                    if top and bottom:
                        line += "█"
                    elif top:
                        line += "▀"
                    elif bottom:
                        line += "▄"
                    else:
                        line += " "
                lines.append(line)
            return "\n".join(lines)
        else:
            # Full block characters
            lines = []
            for row in modules:
                line = "  "
                for cell in row:
                    line += "██" if cell else "  "
                lines.append(line)
            return "\n".join(lines)
    
    except ImportError:
        return ""


# ==============================================================================
# Nostr Identity (secp256k1)
# ==============================================================================

@dataclass
class NostrKeys:
    """Nostr keypair (secp256k1 with BIP-340 Schnorr signatures)"""
    private_key: bytes  # 32 bytes
    public_key: bytes   # 32 bytes (x-only)
    
    @staticmethod
    def generate() -> 'NostrKeys':
        """Generate new Nostr keypair"""
        priv_bytes = secrets.token_bytes(32)
        return NostrKeys.from_private_key(priv_bytes)
    
    @staticmethod
    def from_private_key(priv_bytes: bytes) -> 'NostrKeys':
        """Load from private key bytes"""
        if SECP256K1_LIB == "secp256k1":
            from secp256k1 import PrivateKey as Secp256k1PrivateKey
            sk = Secp256k1PrivateKey(priv_bytes)
            pub_bytes = sk.pubkey.serialize()[1:33]  # x-only
        
        elif SECP256K1_LIB == "coincurve":
            from coincurve import PrivateKey as CoincurvePrivateKey
            sk = CoincurvePrivateKey(priv_bytes)
            # Get x-only pubkey (32 bytes)
            full_pub = sk.public_key.format(compressed=False)  # 65 bytes: 04 + x + y
            pub_bytes = full_pub[1:33]  # x coordinate
        
        else:
            # Pure Python: compute pubkey from private key
            d = _int_from_bytes(priv_bytes)
            P = _point_mul(d)
            pub_bytes = _bytes_from_int(P[0])
        
        return NostrKeys(private_key=priv_bytes, public_key=pub_bytes)
    
    def sign(self, message: bytes) -> bytes:
        """Sign message with BIP-340 Schnorr signature"""
        if SECP256K1_LIB == "secp256k1":
            from secp256k1 import PrivateKey as Secp256k1PrivateKey
            sk = Secp256k1PrivateKey(self.private_key)
            sig = sk.schnorr_sign(message, bip340tag=None, raw=True)
            return sig
        
        else:
            # Use our pure Python BIP-340 implementation
            return schnorr_sign(message, self.private_key)
    
    @property
    def npub(self) -> str:
        """Get npub (bech32 encoded public key)"""
        return bech32_encode("npub", self.public_key)
    
    @property
    def nsec(self) -> str:
        """Get nsec (bech32 encoded private key)"""
        return bech32_encode("nsec", self.private_key)
    
    @property
    def hex_pubkey(self) -> str:
        """Get hex-encoded public key"""
        return self.public_key.hex()


# ==============================================================================
# Encryption Keys (X25519 - separate from Nostr identity)
# ==============================================================================

@dataclass
class X25519KeyPair:
    """X25519 keypair for E2E encryption"""
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    
    def pub_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def priv_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def to_jwk(self) -> dict:
        import base64
        return {
            "kty": "OKP", "crv": "X25519",
            "x": base64.urlsafe_b64encode(self.pub_bytes()).rstrip(b'=').decode()
        }
    
    @staticmethod
    def from_jwk(jwk: dict) -> X25519PublicKey:
        import base64
        x = jwk['x'] + '=' * (4 - len(jwk['x']) % 4) if len(jwk['x']) % 4 else jwk['x']
        return X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x))
    
    @staticmethod
    def generate() -> 'X25519KeyPair':
        priv = X25519PrivateKey.generate()
        return X25519KeyPair(priv, priv.public_key())


# ==============================================================================
# Combined Identity
# ==============================================================================

@dataclass
class Identity:
    """Combined Nostr + Encryption identity"""
    nostr_keys: NostrKeys          # For Nostr protocol (signing events)
    encryption_keys: X25519KeyPair  # For E2E encryption
    created_at: float
    
    @property
    def id(self) -> str:
        """Short ID derived from encryption pubkey"""
        return sha256(self.encryption_keys.pub_bytes())[:8].hex()
    
    @property
    def npub(self) -> str:
        return self.nostr_keys.npub
    
    @property
    def hex_pubkey(self) -> str:
        return self.nostr_keys.hex_pubkey
    
    @staticmethod
    def generate() -> 'Identity':
        return Identity(
            nostr_keys=NostrKeys.generate(),
            encryption_keys=X25519KeyPair.generate(),
            created_at=time.time() * 1000
        )


# ==============================================================================
# Nostr Event
# ==============================================================================

@dataclass
class NostrEvent:
    """Nostr event (NIP-01)"""
    id: str = ""
    pubkey: str = ""
    created_at: int = 0
    kind: int = 1
    tags: list = field(default_factory=list)
    content: str = ""
    sig: str = ""
    
    def serialize_for_id(self) -> str:
        """Serialize for event ID calculation"""
        return json.dumps([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ], separators=(',', ':'), ensure_ascii=False)
    
    def calculate_id(self) -> str:
        """Calculate event ID (SHA256 of serialized event)"""
        serialized = self.serialize_for_id()
        return sha256(serialized.encode()).hex()
    
    def sign(self, keys: NostrKeys):
        """Sign the event"""
        self.pubkey = keys.hex_pubkey
        self.id = self.calculate_id()
        sig_bytes = keys.sign(bytes.fromhex(self.id))
        self.sig = sig_bytes.hex()
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'NostrEvent':
        return NostrEvent(
            id=data.get("id", ""),
            pubkey=data.get("pubkey", ""),
            created_at=data.get("created_at", 0),
            kind=data.get("kind", 1),
            tags=data.get("tags", []),
            content=data.get("content", ""),
            sig=data.get("sig", "")
        )


# ==============================================================================
# Encryption
# ==============================================================================

class Crypto:
    @staticmethod
    def pad(msg: bytes) -> bytes:
        for bucket in PADDING_BUCKETS:
            if len(msg) + 4 <= bucket:
                padded = bytearray(secrets.token_bytes(bucket))
                padded[0:4] = len(msg).to_bytes(4, 'big')
                padded[4:4+len(msg)] = msg
                return bytes(padded)
        raise ValueError("Message too large")
    
    @staticmethod
    def unpad(data: bytes) -> bytes:
        length = int.from_bytes(data[0:4], 'big')
        return data[4:4+length]
    
    @staticmethod
    def derive_key(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
        shared = priv.exchange(pub)
        return HKDF(hashes.SHA256(), 32, None, HKDF_INFO, default_backend()).derive(shared)
    
    @staticmethod
    def encrypt(plaintext: str, sender_kp: X25519KeyPair, recipient_pub: X25519PublicKey) -> dict:
        import base64
        key = Crypto.derive_key(sender_kp.private_key, recipient_pub)
        nonce = secrets.token_bytes(12)
        padded = Crypto.pad(plaintext.encode())
        ct = ChaCha20Poly1305(key).encrypt(nonce, padded, None)
        return {
            "ct": base64.b64encode(ct).decode(),
            "iv": base64.b64encode(nonce).decode(),
            "pk": sender_kp.to_jwk()
        }
    
    @staticmethod
    def decrypt(payload: dict, recipient_kp: X25519KeyPair) -> str:
        import base64
        sender_pub = X25519KeyPair.from_jwk(payload["pk"])
        key = Crypto.derive_key(recipient_kp.private_key, sender_pub)
        ct = base64.b64decode(payload["ct"])
        nonce = base64.b64decode(payload["iv"])
        padded = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
        return Crypto.unpad(padded).decode()


# ==============================================================================
# Privacy Shield (Phase 3 Traffic Analysis Protection)
# ==============================================================================

class PrivacyCrypto:
    """Enhanced cryptographic utilities for privacy protection"""
    
    ENVELOPE_INFO = b"ping-privacy-envelope-v1"
    ROOM_ALIAS_INFO = b"ping-room-alias-v1"
    
    @staticmethod
    def derive_envelope_key(shared_secret: bytes, room_tag: bytes) -> bytes:
        """Derive key for envelope encryption"""
        return HKDF(
            hashes.SHA256(), 32,
            salt=room_tag,
            info=PrivacyCrypto.ENVELOPE_INFO,
            backend=default_backend()
        ).derive(shared_secret)
    
    @staticmethod
    def derive_room_alias(master_secret: bytes, room_tag: str, epoch: int) -> str:
        """Derive rotating room alias"""
        data = f"{room_tag}:{epoch}".encode()
        derived = hmac.new(master_secret, data, hashlib.sha256).digest()
        return derived.hex()[:32]
    
    @staticmethod
    def generate_decoy_room() -> str:
        """Generate random decoy room tag"""
        return secrets.token_hex(16)
    
    @staticmethod
    def pad_envelope(data: bytes, buckets: List[int]) -> bytes:
        """Pad envelope to fixed bucket sizes"""
        for bucket in buckets:
            if len(data) + 4 <= bucket:
                padded = bytearray(secrets.token_bytes(bucket))
                padded[0:4] = struct.pack('>I', len(data))
                padded[4:4+len(data)] = data
                return bytes(padded)
        bucket = ((len(data) + 4) // 1024 + 1) * 1024
        padded = bytearray(secrets.token_bytes(bucket))
        padded[0:4] = struct.pack('>I', len(data))
        padded[4:4+len(data)] = data
        return bytes(padded)
    
    @staticmethod
    def unpad_envelope(data: bytes) -> bytes:
        """Remove padding from envelope"""
        length = struct.unpack('>I', data[0:4])[0]
        return data[4:4+length]
    
    @staticmethod
    def encrypt_envelope(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt envelope data, returns (ciphertext, nonce)"""
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return ciphertext, nonce
    
    @staticmethod
    def decrypt_envelope(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
        """Decrypt envelope data"""
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)


@dataclass
class PrivacyEnvelope:
    """
    Encrypted envelope that hides ALL metadata from relays.
    """
    envelope_type: EnvelopeType
    real_room_tag: str
    sender_identity: str
    sender_username: str
    timestamp: float
    payload: dict
    encryption_pubkey: Optional[dict] = None
    
    def to_bytes(self) -> bytes:
        """Serialize envelope to bytes"""
        data = {
            "t": int(self.envelope_type),
            "r": self.real_room_tag,
            "i": self.sender_identity,
            "u": self.sender_username,
            "ts": self.timestamp,
            "p": self.payload,
        }
        if self.encryption_pubkey:
            data["k"] = self.encryption_pubkey
        return json.dumps(data, separators=(',', ':')).encode()
    
    @staticmethod
    def from_bytes(data: bytes) -> 'PrivacyEnvelope':
        """Deserialize envelope from bytes"""
        d = json.loads(data.decode())
        return PrivacyEnvelope(
            envelope_type=EnvelopeType(d["t"]),
            real_room_tag=d["r"],
            sender_identity=d["i"],
            sender_username=d["u"],
            timestamp=d["ts"],
            payload=d["p"],
            encryption_pubkey=d.get("k"),
        )


class EphemeralIdentityManager:
    """Manages ephemeral Nostr keypairs to prevent identity correlation"""
    
    def __init__(self, master_nostr_privkey: bytes, config: PrivacyConfig):
        self.master_privkey = master_nostr_privkey
        self.config = config
        self.ephemeral_keys: Dict[str, Tuple[bytes, bytes, float]] = {}
        self.session_epoch = int(time.time())
    
    def get_keys_for_room(self, room_tag: str) -> Tuple[bytes, bytes]:
        """Get ephemeral keypair for a room"""
        if not self.config.ephemeral_pubkeys:
            return self._derive_pubkey_from_priv(self.master_privkey)
        
        cache_key = room_tag if self.config.rotate_pubkey_per_room else "global"
        
        if cache_key in self.ephemeral_keys:
            priv, pub, created = self.ephemeral_keys[cache_key]
            age = time.time() - created
            if age < self.config.rotate_pubkey_interval:
                return priv, pub
        
        priv, pub = self._derive_ephemeral_keys(cache_key)
        self.ephemeral_keys[cache_key] = (priv, pub, time.time())
        return priv, pub
    
    def _derive_ephemeral_keys(self, context: str) -> Tuple[bytes, bytes]:
        """Derive ephemeral keypair from master key"""
        epoch_window = int(time.time()) // self.config.rotate_pubkey_interval
        data = f"{context}:{epoch_window}".encode()
        derived = hmac.new(self.master_privkey, data, hashlib.sha256).digest()
        return self._derive_pubkey_from_priv(derived)
    
    def _derive_pubkey_from_priv(self, priv_bytes: bytes) -> Tuple[bytes, bytes]:
        """Derive public key from private key (secp256k1 x-only)"""
        d = _int_from_bytes(priv_bytes)
        P = _point_mul(d)
        pub_bytes = _bytes_from_int(P[0])
        return priv_bytes, pub_bytes
    
    def rotate_now(self, room_tag: Optional[str] = None):
        """Force key rotation"""
        if room_tag:
            cache_key = room_tag if self.config.rotate_pubkey_per_room else "global"
            self.ephemeral_keys.pop(cache_key, None)
        else:
            self.ephemeral_keys.clear()


class RoomTagObfuscator:
    """Obfuscates room tags to prevent relationship analysis"""
    
    def __init__(self, master_secret: bytes, config: PrivacyConfig):
        self.master_secret = master_secret
        self.config = config
        self.decoy_rooms: List[str] = []
        self.alias_cache: Dict[str, Tuple[str, int]] = {}
    
    def get_visible_tag(self, real_room_tag: str) -> str:
        """Get the obfuscated room tag that relays see"""
        if not self.config.room_obfuscation:
            return real_room_tag
        
        epoch = int(time.time()) // self.config.room_alias_rotation
        
        if real_room_tag in self.alias_cache:
            cached_alias, cached_epoch = self.alias_cache[real_room_tag]
            if cached_epoch == epoch:
                return cached_alias
        
        alias = PrivacyCrypto.derive_room_alias(self.master_secret, real_room_tag, epoch)
        self.alias_cache[real_room_tag] = (alias, epoch)
        return alias
    
    def generate_decoy_rooms(self) -> List[str]:
        """Generate decoy room tags"""
        self.decoy_rooms = [
            PrivacyCrypto.generate_decoy_room()
            for _ in range(self.config.decoy_room_count)
        ]
        return self.decoy_rooms
    
    def get_all_subscription_tags(self, real_room_tag: str) -> List[str]:
        """Get all tags to subscribe to (real + decoys)"""
        visible = self.get_visible_tag(real_room_tag)
        
        if not self.config.room_obfuscation:
            return [visible]
        
        if not self.decoy_rooms:
            self.generate_decoy_rooms()
        
        all_tags = [visible] + self.decoy_rooms
        secrets.SystemRandom().shuffle(all_tags)
        return all_tags


class TimingProtector:
    """Adds timing protection to defeat correlation attacks"""
    
    def __init__(self, config: PrivacyConfig):
        self.config = config
    
    async def delay_send(self, send_func: Callable, *args, **kwargs):
        """Send with random delay"""
        if self.config.timing_jitter:
            delay = secrets.randbelow(
                self.config.max_delay_ms - self.config.min_delay_ms
            ) + self.config.min_delay_ms
            await asyncio.sleep(delay / 1000.0)
        await send_func(*args, **kwargs)
    
    def quantize_timestamp(self, ts: Optional[float] = None) -> int:
        """Quantize timestamp to reduce timing precision"""
        if ts is None:
            ts = time.time()
        if not self.config.timing_jitter:
            return int(ts)
        quantum = self.config.timestamp_quantization
        return (int(ts) // quantum) * quantum


class DecoyTrafficGenerator:
    """Generates fake traffic to mask real communication patterns"""
    
    def __init__(self, config: PrivacyConfig):
        self.config = config
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self.send_callback: Optional[Callable] = None
    
    def set_send_callback(self, callback: Callable):
        self.send_callback = callback
    
    async def start(self):
        """Start generating decoy traffic"""
        if not self.config.decoy_traffic or self.running:
            return
        self.running = True
        self._task = asyncio.create_task(self._decoy_loop())
    
    async def stop(self):
        """Stop generating decoy traffic"""
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _decoy_loop(self):
        """Main decoy generation loop"""
        while self.running:
            interval = secrets.randbelow(
                self.config.decoy_max_interval - self.config.decoy_min_interval
            ) + self.config.decoy_min_interval
            await asyncio.sleep(interval)
            if self.running and self.send_callback:
                await self._send_decoy()
    
    async def _send_decoy(self):
        """Send a single decoy message"""
        if not self.send_callback:
            return
        decoy_envelope = PrivacyEnvelope(
            envelope_type=EnvelopeType.DECOY,
            real_room_tag=PrivacyCrypto.generate_decoy_room(),
            sender_identity=secrets.token_hex(8),
            sender_username="",
            timestamp=time.time(),
            payload={"decoy": True},
        )
        try:
            await self.send_callback(decoy_envelope, is_decoy=True)
        except Exception:
            pass


class PrivacyShield:
    """
    Main privacy protection layer for Ping.
    
    Integrates all privacy components:
    - Encrypted envelopes (hide all metadata)
    - Ephemeral identities (prevent tracking)
    - Room obfuscation (hide relationships)
    - Timing protection (defeat correlation)
    - Decoy traffic (mask patterns)
    """
    
    def __init__(
        self,
        master_nostr_privkey: bytes,
        master_encryption_keypair: X25519KeyPair,
        identity_id: str,
        username: str,
        config: Optional[PrivacyConfig] = None
    ):
        self.config = config or PrivacyConfig()
        self.identity_id = identity_id
        self.username = username
        self.master_encryption_keypair = master_encryption_keypair
        self.master_nostr_privkey = master_nostr_privkey
        
        self.ephemeral_manager = EphemeralIdentityManager(master_nostr_privkey, self.config)
        self.room_obfuscator = RoomTagObfuscator(master_nostr_privkey, self.config)
        self.timing_protector = TimingProtector(self.config)
        self.decoy_generator = DecoyTrafficGenerator(self.config)
        
        self.room_keys: Dict[str, bytes] = {}
        self.on_send_event: Optional[Callable] = None
    
    async def initialize(self):
        """Initialize privacy shield"""
        self.decoy_generator.set_send_callback(self._send_decoy_event)
        await self.decoy_generator.start()
    
    async def shutdown(self):
        """Shutdown privacy shield"""
        await self.decoy_generator.stop()
    
    def update_username(self, username: str):
        """Update username"""
        self.username = username
    
    async def protect_outgoing(
        self,
        envelope_type: EnvelopeType,
        real_room_tag: str,
        payload: dict,
        recipient_pub: X25519PublicKey,
        encryption_pubkey_jwk: Optional[dict] = None,
    ) -> dict:
        """
        Protect outgoing message with full privacy shield.
        """
        import base64
        
        envelope = PrivacyEnvelope(
            envelope_type=envelope_type,
            real_room_tag=real_room_tag,
            sender_identity=self.identity_id,
            sender_username=self.username,
            timestamp=time.time() * 1000,
            payload=payload,
            encryption_pubkey=encryption_pubkey_jwk,
        )
        
        envelope_bytes = envelope.to_bytes()
        padded = PrivacyCrypto.pad_envelope(envelope_bytes, self.config.padding_buckets)
        
        shared_secret = self.master_encryption_keypair.private_key.exchange(recipient_pub)
        envelope_key = PrivacyCrypto.derive_envelope_key(
            shared_secret, real_room_tag.encode()
        )
        
        ciphertext, nonce = PrivacyCrypto.encrypt_envelope(padded, envelope_key)
        
        encrypted_payload = {
            "ct": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(nonce).decode(),
            "pk": self.master_encryption_keypair.to_jwk(),
        }
        
        eph_priv, eph_pub = self.ephemeral_manager.get_keys_for_room(real_room_tag)
        visible_tag = self.room_obfuscator.get_visible_tag(real_room_tag)
        quantized_ts = self.timing_protector.quantize_timestamp()
        event_kind = self.config.generic_kind if self.config.use_generic_kind else NostrKind.PING_ROOM_MESSAGE
        
        return {
            "visible_room_tag": visible_tag,
            "ephemeral_pubkey": eph_pub.hex() if isinstance(eph_pub, bytes) else eph_pub,
            "ephemeral_privkey": eph_priv,
            "encrypted_payload": encrypted_payload,
            "event_kind": event_kind,
            "quantized_timestamp": quantized_ts,
        }
    
    async def unprotect_incoming(
        self,
        encrypted_payload: dict,
        expected_room_tag: str,
    ) -> Optional[PrivacyEnvelope]:
        """Unprotect incoming message."""
        import base64
        
        try:
            ciphertext = base64.b64decode(encrypted_payload["ct"])
            nonce = base64.b64decode(encrypted_payload["iv"])
            sender_pub = X25519KeyPair.from_jwk(encrypted_payload["pk"])
            
            shared_secret = self.master_encryption_keypair.private_key.exchange(sender_pub)
            envelope_key = PrivacyCrypto.derive_envelope_key(
                shared_secret, expected_room_tag.encode()
            )
            
            padded = PrivacyCrypto.decrypt_envelope(ciphertext, nonce, envelope_key)
            envelope_bytes = PrivacyCrypto.unpad_envelope(padded)
            envelope = PrivacyEnvelope.from_bytes(envelope_bytes)
            
            if envelope.real_room_tag != expected_room_tag:
                return None
            
            if envelope.envelope_type == EnvelopeType.DECOY:
                return None
            
            return envelope
            
        except Exception:
            return None
    
    async def send_with_protection(self, send_func: Callable, *args, **kwargs):
        """Send with timing protection"""
        await self.timing_protector.delay_send(send_func, *args, **kwargs)
    
    def get_subscription_tags(self, real_room_tag: str) -> List[str]:
        """Get all tags to subscribe to (real + decoys)"""
        return self.room_obfuscator.get_all_subscription_tags(real_room_tag)
    
    async def _send_decoy_event(self, envelope: PrivacyEnvelope, is_decoy: bool = True):
        """Internal callback for sending decoy events"""
        if self.on_send_event:
            await self.on_send_event(envelope, is_decoy=is_decoy)


def create_privacy_shield(identity: 'Identity', username: str, config: Optional[PrivacyConfig] = None) -> PrivacyShield:
    """Factory function to create PrivacyShield from Ping Identity."""
    return PrivacyShield(
        master_nostr_privkey=identity.nostr_keys.private_key,
        master_encryption_keypair=identity.encryption_keys,
        identity_id=identity.id,
        username=username,
        config=config,
    )


# ==============================================================================
# Storage
# ==============================================================================

@dataclass
class Message:
    id: str
    room: str
    sender_id: str
    sender_name: str
    content: str
    timestamp: float


class Storage:
    def __init__(self, memory_only=True):  # Default to memory-only
        self.memory_only = memory_only
        self.messages: dict[str, list[Message]] = {}
        self._identity: Optional[Identity] = None
        self._username: Optional[str] = None
        self._write_enabled = True
        
        if not memory_only:
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
            except (OSError, PermissionError, IOError) as e:
                if DEBUG:
                    print(f"    [debug] Cannot create data dir: {e}")
                self._write_enabled = False
    
    def _safe_write(self, path: Path, content: str) -> bool:
        """Safely write to file, returning False on failure"""
        if not self._write_enabled:
            return False
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            return True
        except (OSError, PermissionError, IOError) as e:
            if DEBUG:
                print(f"    [debug] Write failed {path}: {e}")
            return False
    
    def _safe_read(self, path: Path) -> Optional[str]:
        """Safely read from file, returning None on failure"""
        try:
            if path.exists():
                return path.read_text()
        except (OSError, PermissionError, IOError) as e:
            if DEBUG:
                print(f"    [debug] Read failed {path}: {e}")
        return None
    
    def load_identity(self) -> Identity:
        if self.memory_only:
            if not self._identity:
                self._identity = Identity.generate()
            return self._identity
        
        path = DATA_DIR / "identity.json"
        content = self._safe_read(path)
        if content:
            try:
                import base64
                data = json.loads(content)
                nostr_priv = base64.b64decode(data['nostr_private_key'])
                enc_priv = base64.b64decode(data['encryption_private_key'])
                
                nostr_keys = NostrKeys.from_private_key(nostr_priv)
                enc_key = X25519PrivateKey.from_private_bytes(enc_priv)
                
                return Identity(
                    nostr_keys=nostr_keys,
                    encryption_keys=X25519KeyPair(enc_key, enc_key.public_key()),
                    created_at=data['created_at']
                )
            except Exception as e:
                if DEBUG:
                    print(f"    [debug] Failed to load identity: {e}")
        
        identity = Identity.generate()
        self._save_identity(identity)
        return identity
    
    def _save_identity(self, identity: Identity):
        if self.memory_only:
            return
        import base64
        data = {
            'nostr_private_key': base64.b64encode(identity.nostr_keys.private_key).decode(),
            'encryption_private_key': base64.b64encode(identity.encryption_keys.priv_bytes()).decode(),
            'created_at': identity.created_at
        }
        self._safe_write(DATA_DIR / "identity.json", json.dumps(data))
    
    def load_username(self) -> str:
        if self.memory_only:
            if not self._username:
                self._username = gen_username()
            return self._username
        
        path = DATA_DIR / "username.txt"
        content = self._safe_read(path)
        if content:
            return content.strip()
        
        username = gen_username()
        self._safe_write(path, username)
        return username
    
    def save_username(self, username: str):
        self._username = username
        if not self.memory_only:
            self._safe_write(DATA_DIR / "username.txt", username)
    
    def save_message(self, msg: Message):
        if msg.room not in self.messages:
            self.messages[msg.room] = []
        self.messages[msg.room].append(msg)
    
    def get_messages(self, room: str) -> list[Message]:
        return self.messages.get(room, [])[-50:]
    
    @staticmethod
    def get_config_path() -> Path:
        """Get path to pingconfig.json in script directory"""
        script_dir = Path(__file__).parent.resolve()
        return script_dir / "pingconfig.json"
    
    @staticmethod
    def export_config(identity: Identity, username: str, room: Optional[str] = None, 
                       room_password: Optional[str] = None) -> tuple[Path, bool]:
        """Export session, username, and settings to pingconfig.json"""
        import base64
        
        config_path = Storage.get_config_path()
        
        config = {
            "version": 2,
            "identity": {
                "nostr_private_key": base64.b64encode(identity.nostr_keys.private_key).decode(),
                "nostr_public_key": identity.nostr_keys.hex_pubkey,
                "npub": identity.nostr_keys.npub,
                "encryption_private_key": base64.b64encode(identity.encryption_keys.priv_bytes()).decode(),
                "encryption_public_key": base64.b64encode(identity.encryption_keys.pub_bytes()).decode(),
                "ping_id": identity.id,
                "created_at": identity.created_at,
            },
            "username": username,
            "settings": {
                "sound_enabled": SOUND_ENABLED,
                "legacy_mode": LEGACY_MODE,
                "hardened_mode": HARDENED_MODE,
                "theme": CURRENT_THEME,
                "bg_color": CURRENT_BG,
                "fg_color": CURRENT_FG,
            },
            "room": {
                "name": room,
                "password": room_password,
            } if room else None,
            "exported_at": time.time() * 1000,
        }
        
        try:
            config_path.write_text(json.dumps(config, indent=2))
            return config_path, True
        except Exception as e:
            if DEBUG:
                print(f"    [debug] Export failed: {e}")
            return config_path, False
    
    @staticmethod
    def import_config() -> tuple[Optional[Identity], Optional[str], Optional[dict], Optional[str]]:
        """
        Import identity, username, and settings from pingconfig.json. 
        Returns (identity, username, settings_dict, error)
        settings_dict contains: sound_enabled, legacy_mode, hardened_mode, theme, bg_color, fg_color, room, room_password
        """
        import base64
        
        config_path = Storage.get_config_path()
        
        if not config_path.exists():
            return None, None, None, f"Config file not found: {config_path}"
        
        try:
            content = config_path.read_text()
            config = json.loads(content)
            
            # Extract identity
            id_data = config.get("identity", {})
            nostr_priv = base64.b64decode(id_data["nostr_private_key"])
            enc_priv = base64.b64decode(id_data["encryption_private_key"])
            
            nostr_keys = NostrKeys.from_private_key(nostr_priv)
            enc_key = X25519PrivateKey.from_private_bytes(enc_priv)
            
            identity = Identity(
                nostr_keys=nostr_keys,
                encryption_keys=X25519KeyPair(enc_key, enc_key.public_key()),
                created_at=id_data.get("created_at", time.time() * 1000)
            )
            
            username = config.get("username", gen_username())
            
            # Extract settings (with defaults for v1 configs)
            settings_data = config.get("settings", {})
            room_data = config.get("room", {}) or {}
            
            settings = {
                "sound_enabled": settings_data.get("sound_enabled", True),
                "legacy_mode": settings_data.get("legacy_mode", False),
                "hardened_mode": settings_data.get("hardened_mode", False),
                "theme": settings_data.get("theme"),
                "bg_color": settings_data.get("bg_color"),
                "fg_color": settings_data.get("fg_color"),
                "room": room_data.get("name"),
                "room_password": room_data.get("password"),
            }
            
            return identity, username, settings, None
            
        except json.JSONDecodeError as e:
            return None, None, None, f"Invalid JSON: {e}"
        except KeyError as e:
            return None, None, None, f"Missing field: {e}"
        except Exception as e:
            return None, None, None, f"Load failed: {e}"
    
    def export_all(self, identity: Identity, username: str) -> tuple[str, bool]:
        """Export all data to disk (legacy method for --persist mode)"""
        import base64
        
        success = True
        
        # Ensure directory exists
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError, IOError):
            return str(DATA_DIR), False
        
        # Save identity
        identity_data = {
            'nostr_private_key': base64.b64encode(identity.nostr_keys.private_key).decode(),
            'encryption_private_key': base64.b64encode(identity.encryption_keys.priv_bytes()).decode(),
            'created_at': identity.created_at
        }
        if not self._safe_write(DATA_DIR / "identity.json", json.dumps(identity_data, indent=2)):
            success = False
        
        # Save username
        if not self._safe_write(DATA_DIR / "username.txt", username):
            success = False
        
        # Save messages
        if self.messages:
            messages_data = {}
            for room, msgs in self.messages.items():
                messages_data[room] = [
                    {
                        'id': m.id,
                        'room': m.room,
                        'sender_id': m.sender_id,
                        'sender_name': m.sender_name,
                        'content': m.content,
                        'timestamp': m.timestamp
                    }
                    for m in msgs
                ]
            if not self._safe_write(DATA_DIR / "messages.json", json.dumps(messages_data, indent=2)):
                success = False
        
        return str(DATA_DIR), success
    
    def load_messages(self):
        """Load messages from disk"""
        path = DATA_DIR / "messages.json"
        content = self._safe_read(path)
        if content:
            try:
                data = json.loads(content)
                for room, msgs in data.items():
                    self.messages[room] = [
                        Message(
                            id=m['id'],
                            room=m['room'],
                            sender_id=m['sender_id'],
                            sender_name=m['sender_name'],
                            content=m['content'],
                            timestamp=m['timestamp']
                        )
                        for m in msgs
                    ]
            except Exception as e:
                if DEBUG:
                    print(f"    [debug] Failed to load messages: {e}")


# ==============================================================================
# Peer
# ==============================================================================

@dataclass
class Peer:
    nostr_pubkey: str
    encryption_pubkey: Optional[X25519PublicKey] = None
    identity: str = ""
    username: str = ""
    last_seen: float = 0


# ==============================================================================
# Nostr Relay Connection
# ==============================================================================

class NostrRelay:
    """Connection to a single Nostr relay"""
    
    def __init__(self, url: str):
        self.url = url
        self.ws: Optional[Any] = None
        self.connected = False
        self.subscriptions: dict[str, dict] = {}
    
    async def connect(self) -> bool:
        try:
            # websockets >= 14.0 uses different API
            if WEBSOCKETS_VERSION >= (14, 0):
                from websockets.asyncio.client import connect
                self.ws = await asyncio.wait_for(
                    connect(self.url, ssl=SSL_CONTEXT),
                    timeout=10
                )
            elif WEBSOCKETS_VERSION >= (13, 0):
                # websockets 13.x
                self.ws = await asyncio.wait_for(
                    websockets.connect(self.url, ssl=SSL_CONTEXT, ping_interval=30, ping_timeout=10),
                    timeout=10
                )
            else:
                # websockets < 13.0
                self.ws = await asyncio.wait_for(
                    websockets.connect(self.url, ssl=SSL_CONTEXT, ping_interval=30, ping_timeout=10),
                    timeout=10
                )
            self.connected = True
            return True
        except Exception as e:
            if DEBUG:
                print(f"    [debug] Connection to {self.url} failed: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        self.connected = False
        if self.ws:
            try:
                await self.ws.close()
            except:
                pass
            self.ws = None
    
    async def send(self, message: list):
        if self.ws and self.connected:
            try:
                await self.ws.send(json.dumps(message))
                return True
            except:
                self.connected = False
        return False
    
    async def publish(self, event: NostrEvent) -> bool:
        """Publish event to relay"""
        return await self.send(["EVENT", event.to_dict()])
    
    async def subscribe(self, sub_id: str, filters: dict) -> bool:
        """Subscribe to events"""
        self.subscriptions[sub_id] = filters
        return await self.send(["REQ", sub_id, filters])
    
    async def unsubscribe(self, sub_id: str) -> bool:
        """Unsubscribe"""
        self.subscriptions.pop(sub_id, None)
        return await self.send(["CLOSE", sub_id])
    
    async def receive(self) -> Optional[list]:
        """Receive a message"""
        if not self.ws or not self.connected:
            return None
        try:
            msg = await asyncio.wait_for(self.ws.recv(), timeout=0.1)
            return json.loads(msg)
        except asyncio.TimeoutError:
            return None
        except:
            self.connected = False
            return None


# ==============================================================================
# Nostr Client (Multi-relay)
# ==============================================================================

class NostrClient:
    """Multi-relay Nostr client with Phase 3 Privacy Shield"""
    
    def __init__(self, relay_urls: list[str], identity: Identity, username: str, 
                 legacy_mode: bool = False, hardened_mode: bool = False):
        self.relay_urls = relay_urls
        self.identity = identity
        self.username = username
        self.relays: list[NostrRelay] = []
        self.running = False
        
        # Room state
        self.room_id: Optional[str] = None
        self.room_tag: Optional[str] = None
        
        # Peers
        self.peers: dict[str, Peer] = {}  # nostr_pubkey -> Peer
        
        # Event deduplication - track seen event IDs
        self.seen_events: set[str] = set()
        self.seen_messages: set[str] = set()  # Track message IDs separately
        
        # Callbacks
        self.on_message: Optional[callable] = None
        self.on_peer_join: Optional[callable] = None
        self.on_key_exchange: Optional[callable] = None
        self.on_leave: Optional[callable] = None
        self.on_dm: Optional[callable] = None
        
        # Privacy Shield (Phase 3)
        self.legacy_mode = legacy_mode or LEGACY_MODE
        self.hardened_mode = hardened_mode or HARDENED_MODE
        self.privacy_shield: Optional[PrivacyShield] = None
        
        if self.legacy_mode:
            self.privacy_config = PrivacyConfig.legacy()
        elif self.hardened_mode:
            self.privacy_config = PrivacyConfig.hardened()
            self.privacy_shield = create_privacy_shield(identity, username, self.privacy_config)
        else:
            # Default: envelopes + ephemeral keys
            self.privacy_config = PrivacyConfig.default()
            self.privacy_shield = create_privacy_shield(identity, username, self.privacy_config)
    
    async def connect(self) -> int:
        """Connect to relays, returns number of successful connections"""
        connected = 0
        for url in self.relay_urls:
            relay = NostrRelay(url)
            if await relay.connect():
                self.relays.append(relay)
                connected += 1
                print(f"    ✓ {url}")
            else:
                print(f"    ✗ {url}")
        
        if connected > 0:
            self.running = True
            # Start listener task
            asyncio.create_task(self._listen())
            
            # Initialize Privacy Shield
            if self.privacy_shield:
                await self.privacy_shield.initialize()
                if DEBUG:
                    if self.hardened_mode:
                        print(f"    [debug] Privacy Shield: HARDENED (full protection)")
                    else:
                        print(f"    [debug] Privacy Shield: DEFAULT (envelopes + ephemeral)")
            elif DEBUG:
                print(f"    [debug] Privacy Shield: LEGACY (disabled)")
        
        return connected
    
    async def join_room(self, room_id: str, password: Optional[str] = None):
        """Join a room, optionally with password protection"""
        self.room_id = room_id
        self.room_password = password
        
        # Room tag incorporates password for cryptographic separation
        # Different passwords = different room tags = isolated rooms
        if password:
            room_secret = f"ping-room:{room_id}:{password}"
        else:
            room_secret = f"ping-room:{room_id}"
        self.room_tag = sha256(room_secret.encode()).hex()[:32]
        
        if DEBUG:
            print(f"    [debug] Room tag: {self.room_tag}")
        
        # Clear any old peers
        self.peers.clear()
        self.seen_events.clear()
        
        # Determine event kinds to subscribe to
        if self.privacy_shield and self.privacy_shield.config.use_generic_kind:
            # Privacy mode: subscribe to both protected (generic) and legacy kinds
            kinds = [self.privacy_shield.config.generic_kind,
                     NostrKind.PING_ROOM_MESSAGE, NostrKind.PING_KEY_EXCHANGE, 
                     NostrKind.PING_PRESENCE, NostrKind.PING_LEAVE]
        else:
            kinds = [NostrKind.PING_ROOM_MESSAGE, NostrKind.PING_KEY_EXCHANGE, 
                     NostrKind.PING_PRESENCE, NostrKind.PING_LEAVE]
        
        # Get subscription tags (real + decoys if privacy shield active)
        if self.privacy_shield and self.privacy_shield.config.room_obfuscation:
            subscription_tags = self.privacy_shield.get_subscription_tags(self.room_tag)
            if DEBUG:
                print(f"    [debug] Subscribing to {len(subscription_tags)} tags (1 real + {len(subscription_tags)-1} decoys)")
        else:
            subscription_tags = [self.room_tag]
        
        # Subscribe to all room tags
        for i, tag in enumerate(subscription_tags):
            filters = {
                "kinds": kinds,
                "#r": [tag],
                "since": int(time.time()) - 120  # Last 2 minutes only
            }
            sub_id = f"room:{tag[:8]}"
            for relay in self.relays:
                await relay.subscribe(sub_id, filters)
        
        # Also subscribe to DMs addressed to us (separate subscription)
        dm_filters = {
            "kinds": [NostrKind.PING_DM],
            "#p": [self.identity.hex_pubkey],
            "since": int(time.time()) - 120
        }
        for relay in self.relays:
            await relay.subscribe("ping-dms", dm_filters)
        
        # Small delay to let subscriptions establish
        await asyncio.sleep(0.5)
        
        # Announce presence
        await self._send_presence()
        await asyncio.sleep(0.3)
        await self._send_key_exchange()
        
        # Periodic presence and cleanup
        asyncio.create_task(self._periodic_presence())
        asyncio.create_task(self._cleanup_stale_peers())
    
    async def leave_room(self):
        """Leave current room"""
        if not self.room_tag:
            return
        
        # Announce departure
        await self._send_leave()
        
        sub_id = f"room:{self.room_tag[:8]}"
        for relay in self.relays:
            await relay.unsubscribe(sub_id)
        
        self.room_id = None
        self.room_tag = None
        self.peers.clear()
    
    async def _send_leave(self):
        """Send leave announcement"""
        if not self.room_tag:
            return
        
        content = json.dumps({
            "username": self.username,
            "ping_id": self.identity.id
        })
        
        event = NostrEvent(
            created_at=int(time.time()),
            kind=NostrKind.PING_LEAVE,
            tags=[["r", self.room_tag]],
            content=content
        )
        event.sign(self.identity.nostr_keys)
        
        await self._publish(event)
    
    async def _send_presence(self):
        """Send presence announcement (legacy for discovery)"""
        if not self.room_tag:
            return
        
        # Always send legacy presence for peer discovery
        # Protected presence is sent opportunistically when we have peer keys
        # This avoids rate limiting while still enabling discovery
        content = json.dumps({
            "username": self.username,
            "encryption_pubkey": self.identity.encryption_keys.to_jwk(),
            "ping_id": self.identity.id
        })
        
        event = NostrEvent(
            created_at=int(time.time()),
            kind=NostrKind.PING_PRESENCE,
            tags=[["r", self.room_tag]],
            content=content
        )
        event.sign(self.identity.nostr_keys)
        
        await self._publish(event)
    
    async def _send_key_exchange(self):
        """Send key exchange to room (always includes legacy for discovery)"""
        if not self.room_tag:
            return
        
        # Always send legacy key exchange for peer discovery
        # This is necessary for new peers to establish initial contact
        content = json.dumps({
            "username": self.username,
            "encryption_pubkey": self.identity.encryption_keys.to_jwk(),
            "ping_id": self.identity.id
        })
        
        event = NostrEvent(
            created_at=int(time.time()),
            kind=NostrKind.PING_KEY_EXCHANGE,
            tags=[["r", self.room_tag]],
            content=content
        )
        event.sign(self.identity.nostr_keys)
        
        await self._publish(event)
    
    async def _periodic_presence(self):
        """Send presence periodically"""
        # Initial burst for discovery (just once more after join)
        await asyncio.sleep(3)
        if self.running and self.room_tag:
            await self._send_presence()
        
        # Then regular interval (less frequent)
        while self.running and self.room_tag:
            await asyncio.sleep(60)  # Every minute
            if self.running and self.room_tag:
                await self._send_presence()
    
    async def _cleanup_stale_peers(self):
        """Remove peers that haven't been seen recently"""
        while self.running and self.room_tag:
            await asyncio.sleep(30)  # Check every 30 seconds
            
            now = time.time()
            stale_peers = []
            
            for nostr_pk, peer in self.peers.items():
                # Remove peers not seen in last 3 minutes
                if now - peer.last_seen > 180:
                    stale_peers.append(nostr_pk)
            
            for nostr_pk in stale_peers:
                peer = self.peers.pop(nostr_pk, None)
                if DEBUG and peer:
                    print(f"\r    [debug] Removed stale peer: {peer.username}")
    
    async def send_message(self, text: str) -> bool:
        """Send encrypted message to room"""
        if not self.room_tag:
            return False
        
        # Get peers with encryption keys
        recipients = [(pk, p) for pk, p in self.peers.items() if p.encryption_pubkey]
        if not recipients:
            print("  No peers with encryption keys yet")
            return False
        
        msg_id = gen_msg_id()
        ts = time.time() * 1000
        
        message_data = {
            "c": text,
            "ts": ts,
            "u": self.username,
            "id": msg_id
        }
        
        # Determine if we should use protected envelopes (default and hardened modes)
        use_envelope = (self.privacy_shield and 
                       self.privacy_shield.config.envelope_enabled)
        
        # Send to each peer
        for nostr_pk, peer in recipients:
            try:
                if DEBUG:
                    print(f"    [debug] Sending to {peer.username} (nostr: {nostr_pk[:12]}...)")
                
                if use_envelope:
                    # Privacy mode: use envelope
                    protected = await self.privacy_shield.protect_outgoing(
                        envelope_type=EnvelopeType.MESSAGE,
                        real_room_tag=self.room_tag,
                        payload=message_data,
                        recipient_pub=peer.encryption_pubkey,
                    )
                    
                    event = NostrEvent(
                        created_at=protected["quantized_timestamp"],
                        kind=protected["event_kind"],
                        tags=[
                            ["r", protected["visible_room_tag"]],
                            ["p", nostr_pk]
                        ],
                        content=json.dumps({
                            "protected": True,
                            "payload": protected["encrypted_payload"],
                        })
                    )
                    
                    # Sign with ephemeral key
                    eph_priv = protected["ephemeral_privkey"]
                    eph_pub = protected["ephemeral_pubkey"]
                    event.pubkey = eph_pub if isinstance(eph_pub, str) else eph_pub.hex()
                    event.id = event.calculate_id()
                    sig_bytes = schnorr_sign(bytes.fromhex(event.id), eph_priv)
                    event.sig = sig_bytes.hex()
                    
                    # Use timing protection only in hardened mode
                    if self.hardened_mode and self.privacy_shield.config.timing_jitter:
                        await self.privacy_shield.send_with_protection(self._publish, event)
                    else:
                        await self._publish(event)
                else:
                    # Legacy mode: use legacy format
                    encrypted = Crypto.encrypt(
                        json.dumps(message_data),
                        self.identity.encryption_keys,
                        peer.encryption_pubkey
                    )
                    
                    event = NostrEvent(
                        created_at=int(time.time()),
                        kind=NostrKind.PING_ROOM_MESSAGE,
                        tags=[
                            ["r", self.room_tag],
                            ["p", nostr_pk]
                        ],
                        content=json.dumps(encrypted)
                    )
                    
                    # Legacy mode: use master key for signing
                    event.sign(self.identity.nostr_keys)
                    
                    await self._publish(event)
            except Exception as e:
                if DEBUG:
                    print(f"    [debug] Send error: {e}")
        
        return True
    
    async def send_dm(self, username: str, text: str) -> bool:
        """Send direct message to a specific peer by username"""
        # Find peer by username
        target_peer = None
        target_pk = None
        for pk, peer in self.peers.items():
            if peer.username.lower() == username.lower() and peer.encryption_pubkey:
                target_peer = peer
                target_pk = pk
                break
        
        if not target_peer:
            return False
        
        msg_id = gen_msg_id()
        ts = time.time() * 1000
        
        message_data = {
            "c": text,
            "ts": ts,
            "u": self.username,
            "id": msg_id,
            "dm": True  # Mark as DM
        }
        
        try:
            encrypted = Crypto.encrypt(
                json.dumps(message_data),
                self.identity.encryption_keys,
                target_peer.encryption_pubkey
            )
            
            event = NostrEvent(
                created_at=int(time.time()),
                kind=NostrKind.PING_DM,
                tags=[
                    ["p", target_pk]  # Tag recipient only (no room tag for privacy)
                ],
                content=json.dumps(encrypted)
            )
            event.sign(self.identity.nostr_keys)
            
            await self._publish(event)
            return True
        except Exception as e:
            if DEBUG:
                print(f"    [debug] DM send error: {e}")
            return False
    
    async def reconnect(self) -> int:
        """Reconnect to relays without leaving room"""
        # Disconnect existing relays
        for relay in self.relays:
            await relay.disconnect()
        self.relays.clear()
        
        # Reconnect
        connected = 0
        for url in self.relay_urls:
            relay = NostrRelay(url)
            if await relay.connect():
                self.relays.append(relay)
                connected += 1
                print(f"    ✓ {url}")
            else:
                print(f"    ✗ {url}")
        
        if connected > 0:
            # Re-subscribe to room if in one
            if self.room_tag:
                filters = {
                    "kinds": [NostrKind.PING_ROOM_MESSAGE, NostrKind.PING_KEY_EXCHANGE, 
                              NostrKind.PING_PRESENCE, NostrKind.PING_LEAVE, NostrKind.PING_DM],
                    "#r": [self.room_tag],
                    "since": int(time.time()) - 120
                }
                sub_id = f"room:{self.room_tag[:8]}"
                for relay in self.relays:
                    await relay.subscribe(sub_id, filters)
                
                # Also subscribe to DMs addressed to us
                dm_filters = {
                    "kinds": [NostrKind.PING_DM],
                    "#p": [self.identity.hex_pubkey],
                    "since": int(time.time()) - 120
                }
                for relay in self.relays:
                    await relay.subscribe("dms", dm_filters)
                
                # Re-announce presence
                await self._send_presence()
        
        return connected
    
    async def _publish(self, event: NostrEvent):
        """Publish event to all connected relays"""
        success_count = 0
        for relay in self.relays:
            if await relay.publish(event):
                success_count += 1
        return success_count > 0
    
    async def _listen(self):
        """Listen for events from all relays"""
        while self.running:
            # Poll all relays concurrently
            tasks = [relay.receive() for relay in self.relays if relay.connected]
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for msg in results:
                    if msg and not isinstance(msg, Exception):
                        await self._handle_message(msg)
            
            await asyncio.sleep(0.05)  # 50ms between polls
    
    async def _handle_message(self, msg: list):
        """Handle incoming Nostr message"""
        if len(msg) < 2:
            return
        
        msg_type = msg[0]
        
        if msg_type == "EVENT" and len(msg) >= 3:
            event = NostrEvent.from_dict(msg[2])
            await self._handle_event(event)
        
        elif msg_type == "OK":
            # Event accepted by relay
            if len(msg) >= 4 and msg[2] == False:
                # Only show rejections in debug mode
                if DEBUG:
                    print(f"\r    [relay] Rejected: {msg[3]}")
        
        elif msg_type == "NOTICE":
            if DEBUG and len(msg) >= 2:
                print(f"\r    [relay] {msg[1]}")
    
    async def _handle_event(self, event: NostrEvent):
        """Handle incoming event (protected or legacy)"""
        # Ignore our own events (check both master and ephemeral pubkeys)
        if event.pubkey == self.identity.hex_pubkey:
            return
        
        # Also ignore events from our own ephemeral keys
        if self.privacy_shield:
            try:
                eph_priv, eph_pub = self.privacy_shield.ephemeral_manager.get_keys_for_room(self.room_tag or "")
                eph_pub_hex = eph_pub.hex() if isinstance(eph_pub, bytes) else eph_pub
                if event.pubkey == eph_pub_hex:
                    return
            except:
                pass
        
        # Deduplicate events (same event from multiple relays)
        if event.id in self.seen_events:
            return
        self.seen_events.add(event.id)
        
        # Limit seen_events size to prevent memory growth
        if len(self.seen_events) > 10000:
            self.seen_events = set(list(self.seen_events)[5000:])
        
        if DEBUG:
            print(f"\r    [debug] Received event kind={event.kind} from {event.pubkey[:12]}")
        
        # Check if this is a protected message
        try:
            content = json.loads(event.content) if event.content else {}
            is_protected = content.get("protected", False)
        except:
            is_protected = False
            content = {}
        
        # Handle protected messages
        if is_protected and self.privacy_shield and self.room_tag:
            await self._handle_protected_event(event, content)
            return
        
        # Legacy message handling
        if event.kind == NostrKind.PING_PRESENCE:
            await self._handle_presence(event)
        
        elif event.kind == NostrKind.PING_KEY_EXCHANGE:
            await self._handle_key_exchange(event)
        
        elif event.kind == NostrKind.PING_ROOM_MESSAGE:
            await self._handle_room_message(event)
        
        elif event.kind == NostrKind.PING_LEAVE:
            await self._handle_leave(event)
        
        elif event.kind == NostrKind.PING_DM:
            await self._handle_dm(event)
        
        # Also handle generic kind 4 (NIP-04) for protected messages
        elif event.kind == NostrKind.ENCRYPTED_DM and is_protected:
            await self._handle_protected_event(event, content)
    
    async def _handle_protected_event(self, event: NostrEvent, content: dict):
        """Handle privacy-protected event"""
        if not self.privacy_shield or not self.room_tag:
            return
        
        payload = content.get("payload")
        if not payload:
            if DEBUG:
                print(f"\r    [debug] Protected event has no payload")
            return
        
        if DEBUG:
            print(f"\r    [debug] Trying to decrypt protected event from {event.pubkey[:12]}...")
        
        # Try to decrypt envelope
        envelope = await self.privacy_shield.unprotect_incoming(
            encrypted_payload=payload,
            expected_room_tag=self.room_tag,
        )
        
        if envelope is None:
            # Could be decoy or wrong room - silently ignore
            if DEBUG:
                print(f"\r    [debug] Failed to decrypt envelope (decoy or wrong key?)")
            return
        
        if DEBUG:
            print(f"\r    [debug] Decrypted envelope type={envelope.envelope_type}, from={envelope.sender_username}")
        
        if envelope is None:
            # Could be decoy or wrong room - silently ignore
            return
        
        # Route based on envelope type
        if envelope.envelope_type == EnvelopeType.PRESENCE:
            await self._handle_protected_presence(event, envelope)
        
        elif envelope.envelope_type == EnvelopeType.KEY_EXCHANGE:
            await self._handle_protected_key_exchange(event, envelope)
        
        elif envelope.envelope_type == EnvelopeType.MESSAGE:
            await self._handle_protected_message(event, envelope)
        
        elif envelope.envelope_type == EnvelopeType.LEAVE:
            await self._handle_protected_leave(event, envelope)
    
    async def _handle_protected_presence(self, event: NostrEvent, envelope: PrivacyEnvelope):
        """Handle protected presence announcement"""
        nostr_pk = event.pubkey
        
        if nostr_pk not in self.peers:
            self.peers[nostr_pk] = Peer(nostr_pubkey=nostr_pk)
            if self.on_peer_join:
                self.on_peer_join(nostr_pk)
            await self._send_key_exchange()
        
        peer = self.peers[nostr_pk]
        peer.username = envelope.sender_username
        peer.identity = envelope.sender_identity
        peer.last_seen = time.time()
        
        if envelope.encryption_pubkey:
            peer.encryption_pubkey = X25519KeyPair.from_jwk(envelope.encryption_pubkey)
    
    async def _handle_protected_key_exchange(self, event: NostrEvent, envelope: PrivacyEnvelope):
        """Handle protected key exchange"""
        nostr_pk = event.pubkey
        
        is_new_peer = nostr_pk not in self.peers
        if is_new_peer:
            self.peers[nostr_pk] = Peer(nostr_pubkey=nostr_pk)
        
        peer = self.peers[nostr_pk]
        peer.username = envelope.sender_username
        peer.identity = envelope.sender_identity
        peer.last_seen = time.time()
        
        if envelope.encryption_pubkey:
            had_key = peer.encryption_pubkey is not None
            peer.encryption_pubkey = X25519KeyPair.from_jwk(envelope.encryption_pubkey)
            
            if not had_key and self.on_key_exchange:
                self.on_key_exchange(nostr_pk, peer.username, peer.identity)
            
            if is_new_peer:
                await self._send_key_exchange()
    
    async def _handle_protected_message(self, event: NostrEvent, envelope: PrivacyEnvelope):
        """Handle protected message"""
        payload = envelope.payload
        msg_id = payload.get("id", "")
        
        if msg_id in self.seen_messages:
            return
        self.seen_messages.add(msg_id)
        
        if self.on_message:
            self.on_message(
                event.pubkey,
                envelope.sender_username,
                payload.get("c", ""),
                envelope.timestamp,
                msg_id
            )
    
    async def _handle_protected_leave(self, event: NostrEvent, envelope: PrivacyEnvelope):
        """Handle protected leave announcement"""
        nostr_pk = event.pubkey
        
        peer = self.peers.pop(nostr_pk, None)
        if peer and self.on_leave:
            self.on_leave(nostr_pk, envelope.sender_username)
    
    async def _handle_presence(self, event: NostrEvent):
        """Handle presence announcement"""
        try:
            # Ignore old presence events (older than 2 minutes)
            event_age = time.time() - event.created_at
            if event_age > 120:  # 2 minutes
                if DEBUG:
                    print(f"\r    [debug] Ignoring stale presence from {event.pubkey[:12]} (age: {int(event_age)}s)")
                return
            
            content = json.loads(event.content)
            nostr_pk = event.pubkey
            
            if nostr_pk not in self.peers:
                self.peers[nostr_pk] = Peer(nostr_pubkey=nostr_pk)
                if self.on_peer_join:
                    self.on_peer_join(nostr_pk)
                # Send our key exchange
                await self._send_key_exchange()
            
            peer = self.peers[nostr_pk]
            peer.username = content.get("username", "unknown")
            peer.identity = content.get("ping_id", "")
            peer.last_seen = time.time()
            
            # Extract encryption key
            enc_jwk = content.get("encryption_pubkey")
            if enc_jwk:
                peer.encryption_pubkey = X25519KeyPair.from_jwk(enc_jwk)
                
        except Exception as e:
            pass
    
    async def _handle_key_exchange(self, event: NostrEvent):
        """Handle key exchange"""
        try:
            # Ignore old key exchange events (older than 2 minutes)
            event_age = time.time() - event.created_at
            if event_age > 120:  # 2 minutes
                if DEBUG:
                    print(f"\r    [debug] Ignoring stale key_exchange from {event.pubkey[:12]} (age: {int(event_age)}s)")
                return
            
            content = json.loads(event.content)
            nostr_pk = event.pubkey
            
            is_new_peer = nostr_pk not in self.peers
            
            if is_new_peer:
                self.peers[nostr_pk] = Peer(nostr_pubkey=nostr_pk)
            
            peer = self.peers[nostr_pk]
            peer.username = content.get("username", "unknown")
            peer.identity = content.get("ping_id", "")
            peer.last_seen = time.time()
            
            enc_jwk = content.get("encryption_pubkey")
            if enc_jwk:
                had_key = peer.encryption_pubkey is not None
                peer.encryption_pubkey = X25519KeyPair.from_jwk(enc_jwk)
                
                # Notify if this is a new key (first time we got their key)
                if not had_key and self.on_key_exchange:
                    self.on_key_exchange(nostr_pk, peer.username, peer.identity)
                
                # Only send our key back once when we first see this peer
                if is_new_peer:
                    await self._send_key_exchange()
                
        except Exception as e:
            pass
    
    async def _handle_room_message(self, event: NostrEvent):
        """Handle encrypted room message"""
        # Check if we're the recipient
        is_for_us = False
        for tag in event.tags:
            if len(tag) >= 2 and tag[0] == "p" and tag[1] == self.identity.hex_pubkey:
                is_for_us = True
                break
        
        if not is_for_us:
            if DEBUG:
                p_tags = [t[1][:12] for t in event.tags if t[0] == "p"]
                print(f"\r    [debug] Message not for us. Tagged for: {p_tags}, we are: {self.identity.hex_pubkey[:12]}")
            return
        
        try:
            payload = json.loads(event.content)
            decrypted = Crypto.decrypt(payload, self.identity.encryption_keys)
            content = json.loads(decrypted)
            
            # Get sender info - try peer lookup first, fall back to message content
            sender_pk = event.pubkey
            peer = self.peers.get(sender_pk)
            # Username is in encrypted content, use that as primary source
            sender_name = content.get("u") or (peer.username if peer else "unknown")
            
            if self.on_message:
                self.on_message(
                    sender_pk,
                    sender_name,
                    content.get("c", ""),
                    content.get("ts", time.time() * 1000),
                    content.get("id", gen_msg_id())
                )
        except Exception as e:
            if DEBUG:
                print(f"\r    [debug] Decrypt error: {e}")
    
    async def _handle_leave(self, event: NostrEvent):
        """Handle leave/disconnect announcement"""
        try:
            # Ignore old leave events
            event_age = time.time() - event.created_at
            if event_age > 60:  # 1 minute - leave events should be recent
                return
            
            content = json.loads(event.content)
            nostr_pk = event.pubkey
            
            # Remove peer from list
            peer = self.peers.pop(nostr_pk, None)
            if peer and self.on_leave:
                self.on_leave(nostr_pk, peer.username)
                
        except Exception as e:
            if DEBUG:
                print(f"\r    [debug] Leave event error: {e}")
    
    async def _handle_dm(self, event: NostrEvent):
        """Handle direct message"""
        # Check if we're the recipient
        is_for_us = False
        for tag in event.tags:
            if len(tag) >= 2 and tag[0] == "p" and tag[1] == self.identity.hex_pubkey:
                is_for_us = True
                break
        
        if not is_for_us:
            return
        
        try:
            payload = json.loads(event.content)
            decrypted = Crypto.decrypt(payload, self.identity.encryption_keys)
            content = json.loads(decrypted)
            
            sender_pk = event.pubkey
            peer = self.peers.get(sender_pk)
            sender_name = peer.username if peer else content.get("u", "unknown")
            
            if self.on_dm:
                self.on_dm(
                    sender_pk,
                    sender_name,
                    content.get("c", ""),
                    content.get("ts", time.time() * 1000),
                    content.get("id", gen_msg_id())
                )
        except Exception as e:
            if DEBUG:
                print(f"\r    [debug] DM decrypt error: {e}")
    
    async def disconnect(self):
        """Disconnect from all relays"""
        self.running = False
        
        # Shutdown Privacy Shield
        if self.privacy_shield:
            await self.privacy_shield.shutdown()
        
        for relay in self.relays:
            await relay.disconnect()
        self.relays.clear()


# ==============================================================================
# Main CLI
# ==============================================================================

class PingNostrCLI:
    def __init__(self, room: Optional[str], password: Optional[str], username: Optional[str], 
                 memory_only: bool = True, legacy_mode: bool = False, hardened_mode: bool = False,
                 load_config: bool = False):
        global SOUND_ENABLED, LEGACY_MODE, HARDENED_MODE
        
        self.storage = Storage(memory_only)
        self.memory_only = memory_only
        self.legacy_mode = legacy_mode
        self.hardened_mode = hardened_mode
        
        # Load identity - either from config file, storage, or generate new
        if load_config:
            loaded_identity, loaded_username, settings, error = Storage.import_config()
            if loaded_identity:
                self.identity = loaded_identity
                self.username = username or loaded_username or gen_username()
                print(f"  ✓ Loaded config from {Storage.get_config_path()}")
                
                # Apply settings from config
                if settings:
                    # Sound
                    SOUND_ENABLED = settings.get("sound_enabled", True)
                    
                    # Privacy modes (CLI flags override config)
                    if not legacy_mode and not hardened_mode:
                        LEGACY_MODE = settings.get("legacy_mode", False)
                        HARDENED_MODE = settings.get("hardened_mode", False)
                        self.legacy_mode = LEGACY_MODE
                        self.hardened_mode = HARDENED_MODE
                    
                    # Theme/colors
                    theme = settings.get("theme")
                    bg_color = settings.get("bg_color")
                    fg_color = settings.get("fg_color")
                    
                    if theme:
                        apply_theme(theme)
                    elif bg_color or fg_color:
                        apply_terminal_color(bg_color, fg_color)
                    
                    # Room (CLI args override config)
                    if not room and settings.get("room"):
                        room = settings.get("room")
                        password = settings.get("room_password")
            else:
                print(f"  ⚠️  {error}")
                print(f"  Generating new identity...")
                self.identity = self.storage.load_identity()
                self.username = username or self.storage.load_username()
        else:
            self.identity = self.storage.load_identity()
            self.username = username or self.storage.load_username()
        
        self.initial_room = room
        self.initial_password = password
        
        self.current_room: Optional[str] = None
        self.current_password: Optional[str] = None  # Track if room is password-protected
        self.client: Optional[NostrClient] = None
        self.running = False
        
        # Setup readline for history and tab completion
        self._setup_readline()
    
    def _setup_readline(self):
        """Setup readline for command history and tab completion"""
        try:
            import readline
            
            # Enable history
            readline.set_history_length(1000)
            
            # Load history from file if exists
            history_file = DATA_DIR / "history"
            if history_file.exists():
                try:
                    readline.read_history_file(str(history_file))
                except Exception:
                    pass
            
            # Setup tab completion
            readline.set_completer(self._completer)
            readline.set_completer_delims(' ')
            readline.parse_and_bind('tab: complete')
            
            # Store readline module for later use
            self._readline = readline
            self._history_file = history_file
        except ImportError:
            # readline not available (Windows without pyreadline)
            self._readline = None
            self._history_file = None
    
    def _save_history(self):
        """Save command history to file"""
        if self._readline and self._history_file:
            try:
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                self._readline.write_history_file(str(self._history_file))
            except Exception:
                pass
    
    def _completer(self, text: str, state: int) -> Optional[str]:
        """Tab completion handler"""
        try:
            import readline
            
            # Get the full line buffer
            line = readline.get_line_buffer()
            
            # Check if we're completing a /dm command
            if line.startswith('/dm ') or line.startswith('/d '):
                return self._complete_dm(line, text, state)
            
            # Check if we're completing a /color command
            if line.startswith('/color '):
                return self._complete_color(line, text, state)
            
            # Check if we're completing a command
            if line.startswith('/'):
                return self._complete_command(text, state)
            
            return None
        except Exception:
            return None
    
    def _complete_command(self, text: str, state: int) -> Optional[str]:
        """Complete command names"""
        commands = [
            '/join', '/leave', '/invite', '/peers', '/name', '/dm',
            '/reconnect', '/color', '/printsession', '/relays', '/info', '/clear',
            '/save', '/update', '/wipe', '/quit', '/help'
        ]
        
        # Filter commands that match
        if text.startswith('/'):
            matches = [c for c in commands if c.startswith(text)]
        else:
            matches = [c for c in commands if c.startswith('/' + text)]
        
        if state < len(matches):
            return matches[state]
        return None
    
    def _complete_dm(self, line: str, text: str, state: int) -> Optional[str]:
        """Complete peer usernames for /dm command"""
        if not self.client or not self.client.peers:
            return None
        
        # Get list of peer usernames
        usernames = [p.username for p in self.client.peers.values() if p.username]
        
        # Determine what we're completing
        parts = line.split()
        
        if len(parts) == 1:
            # Just "/dm" - show all usernames
            prefix = ""
        elif len(parts) == 2 and not line.endswith(' '):
            # "/dm par" - completing username
            prefix = parts[1].lower()
        else:
            # Already have username, no completion
            return None
        
        # Filter usernames that match prefix
        matches = [u for u in usernames if u.lower().startswith(prefix)]
        matches.sort()
        
        if state < len(matches):
            return matches[state] + ' '  # Add space after username
        return None
    
    def _complete_color(self, line: str, text: str, state: int) -> Optional[str]:
        """Complete color and theme names for /color command"""
        # Colors
        color_names = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white',
                       'lblack', 'lred', 'lgreen', 'lyellow', 'lblue', 'lmagenta', 'lcyan', 'lwhite',
                       'gray', 'grey', 'default', 'none', 'reset', '-']
        
        # Themes
        theme_names = list(THEMES.keys())
        
        # Special commands
        special = ['list', 'themes', 'help']
        
        parts = line.split()
        
        # Determine which argument we're completing
        if len(parts) == 1:
            # Just "/color" - show themes, colors, and special commands
            prefix = ""
            all_options = theme_names + color_names + special
        elif len(parts) == 2 and not line.endswith(' '):
            # "/color ma" - completing first arg
            prefix = parts[1].lower()
            all_options = theme_names + color_names + special
        elif len(parts) == 2 and line.endswith(' '):
            # "/color blue " - completing fg (only colors, not themes)
            prefix = ""
            all_options = color_names
        elif len(parts) == 3 and not line.endswith(' '):
            # "/color blue whi" - completing fg
            prefix = parts[2].lower()
            all_options = color_names
        else:
            return None
        
        matches = [c for c in all_options if c.startswith(prefix)]
        matches = sorted(set(matches))  # Remove duplicates and sort
        
        if state < len(matches):
            return matches[state] + ' '
        return None
    
    def _banner(self):
        print('''
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+= +#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.      .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#:          @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.          +@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*          +@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@#-   =%@@@@@@@@@@@@@@@@          +*+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@*       #@@@@@@@@@@@@@@@+              =+++#@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@=        @@@@@@@@@@@@@@@@#                   =+@@@@@@@@@@@@@@@@@@@
@@@@@@@@#       -@@@@@@@@@@@@@@#=                       =+%@@@@@@@@@@@@@@@
@@@@@@@@@@+.     =#@@@@@@@@@@*:                            .=+#@@@@@@@@@@@
@@@@@@@@@@@@#      .+*@@@@+                                    .#@@@@@@@@@
@@@@@@@@@@@@@@+ =       -                                 :       -+@@@@@@
@@* #@@@@@@@@@@@@#:                                  #@*+#@@#=      :#@@@@
@@#+%@@@@@@@@@@@@@@#=      :=+-                     :@@@@@@@@@@+=-  .#@@@@
@@@@@@@@@@@@@@@@@@@@@@@++#@@@@@@+                   -@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                   @@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                 =@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                +@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+               =@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+               +@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:               :@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                 %@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                  =@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                    @@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@ Decentralized E2E Encrypted Messenger @@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
''')
        print(f"  Version:   {APP_VERSION}")
        print(f"  Username:  {self.username}")
        print(f"  Ping ID:   {self.identity.id}")
        print(f"  Nostr:     {self.identity.npub[:20]}...")
        if self.memory_only:
            print(f"  Mode:      Ephemeral (use /save to export, --load to restore)")
        else:
            print(f"  Mode:      Persistent")
            print(f"  Data:      {DATA_DIR}")
        print(f"  Relays:    {len(NOSTR_RELAYS)} configured")
        
        # Privacy status
        if self.legacy_mode:
            print(f"  Privacy:   Legacy (E2E only)")
        elif self.hardened_mode:
            print(f"  Privacy:   X25519+ChaCha20-Poly1305+HKDF (hardened)")
        else:
            print(f"  Privacy:   X25519+ChaCha20-Poly1305+HKDF")
        print()
    
    def _quick_help(self):
        """Show compact command reference on startup"""
        print("""  ┌─ Quick Reference ─────────────────────────────────┐
  │ Room:  /join /leave /invite /peers              │
  │ Chat:  /dm /name  View: /info /relays /clear    │
  │ Config: /color /sound  Data: /save /load /wipe  │
  └─────────────────────── Type /help for details ──┘
""")

    def _help(self):
        """Show full command help"""
        print("""
  ════════════════════════════════════════════════════
                        COMMANDS
  ════════════════════════════════════════════════════

  ROOM
    /join <room> [pass]   Join room (optional password)
    /leave                Leave current room
    /invite               Generate invite code + QR
    /peers                Show connected peers
    /reconnect            Reconnect to relays

  CHAT
    /dm <user> <msg>      Direct message to peer
    /name <username>      Change display name

  VIEW
    /info                 Show session info
    /relays               Show relay status
    /clear                Clear screen

  CONFIG
    /color [theme|bg fg]  Set colors (/color themes)
    /sound [on|off|test]  Toggle sound notifications

  SESSION
    /printsession         Show encryption keys
    /save                 Export to pingconfig.json
    /load                 Import from pingconfig.json

  MISC
    /update [apply]       Check/install updates
    /wipe                 Reset all data
    /quit                 Exit Ping

  ════════════════════════════════════════════════════
  Type any text to send encrypted message to room.
  ════════════════════════════════════════════════════
""")
    
    async def run(self):
        self._banner()
        self._quick_help()
        self.running = True
        
        if self.initial_room:
            await self._join(self.initial_room, self.initial_password)
        
        while self.running:
            try:
                # Show lock icon if room is password-protected
                if self.current_room:
                    lock = "🔒" if self.current_password else ""
                    prompt = f"[{self.current_room}]{lock} > "
                else:
                    prompt = "> "
                line = await asyncio.get_event_loop().run_in_executor(None, lambda: input(prompt))
                if line:
                    await self._handle(line.strip())
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye!")
                break
        
        # Save command history
        self._save_history()
        await self._cleanup()
    
    async def _handle(self, line: str):
        if line.startswith('/'):
            parts = line[1:].split(maxsplit=1)
            cmd, args = parts[0].lower(), parts[1] if len(parts) > 1 else ""
            
            if cmd in ('quit', 'q', 'exit'):
                self.running = False
            elif cmd in ('join', 'j'):
                if args:
                    await self._parse_join(args)
                else:
                    print("  Usage: /join <room> [password]")
            elif cmd in ('leave', 'l'):
                await self._leave()
            elif cmd in ('peers', 'p'):
                self._peers()
            elif cmd in ('dm', 'd'):
                await self._dm(args) if args else print("  Usage: /dm <username> <message>")
            elif cmd == 'reconnect':
                await self._reconnect()
            elif cmd in ('name', 'n'):
                if args:
                    self.username = args
                    self.storage.save_username(args)
                    if self.client:
                        self.client.username = args
                    print(f"  Name: {args}")
                else:
                    print("  Usage: /name <username>")
            elif cmd == 'relays':
                self._relays()
            elif cmd in ('info', 'i'):
                self._info()
            elif cmd == 'clear':
                self._clear()
            elif cmd == 'color':
                self._color(args)
            elif cmd == 'sound':
                self._sound(args)
            elif cmd == 'save':
                self._save()
            elif cmd == 'load':
                self._load()
            elif cmd == 'printsession':
                self._printsession()
            elif cmd == 'invite':
                self._invite()
            elif cmd == 'update':
                await self._update(args)
            elif cmd == 'wipe':
                await self._wipe()
            elif cmd == 'help':
                self._help()
            else:
                print(f"  Unknown: /{cmd}")
        
        elif self.current_room:
            await self._send(line)
        else:
            print("  Join a room first: /join <room> [password]")
    
    async def _parse_join(self, args: str):
        """Parse join command arguments: /join <room> [password]"""
        parts = args.split(maxsplit=1)
        room = parts[0]
        password = parts[1] if len(parts) > 1 else None
        await self._join(room, password)
    
    async def _join(self, room: str, password: Optional[str] = None):
        if self.current_room:
            await self._leave()
        
        # Show room info
        if password:
            print(f"\n  Joining room: {room} 🔒 (password-protected)")
        else:
            print(f"\n  Joining room: {room}")
        print(f"  Connecting to relays...")
        
        self.client = NostrClient(NOSTR_RELAYS, self.identity, self.username, 
                                   legacy_mode=self.legacy_mode, 
                                   hardened_mode=self.hardened_mode)
        self.client.on_message = self._on_message
        self.client.on_peer_join = self._on_peer_join
        self.client.on_key_exchange = self._on_key_exchange
        self.client.on_leave = self._on_leave
        self.client.on_dm = self._on_dm
        
        connected = await self.client.connect()
        
        if connected > 0:
            await self.client.join_room(room, password)
            self.current_room = room
            self.current_password = password
            
            lock = " 🔒" if password else ""
            print(f"\n  ✓ Joined: {room}{lock} ({connected} relays)")
            print(f"  Waiting for peers...\n")
        else:
            print(f"  ✗ Failed to connect to any relay")
            self.client = None
    
    async def _leave(self):
        if not self.current_room:
            return
        
        print(f"  Leaving: {self.current_room}")
        if self.client:
            await self.client.leave_room()
            await self.client.disconnect()
            self.client = None
        self.current_room = None
        self.current_password = None
    
    async def _send(self, text: str):
        if not self.client:
            return
        
        peers_with_keys = sum(1 for p in self.client.peers.values() if p.encryption_pubkey)
        if peers_with_keys == 0:
            print("  No peers with keys yet")
            return
        
        # Save own message
        msg = Message(
            id=gen_msg_id(),
            room=self.current_room or '',
            sender_id=self.identity.id,
            sender_name=self.username,
            content=text,
            timestamp=time.time() * 1000
        )
        self.storage.save_message(msg)
        
        # Send
        await self.client.send_message(text)
        
        # Display with own fingerprint
        t = time.strftime("%H:%M", time.localtime(msg.timestamp / 1000))
        fingerprint = self.identity.id[:8]
        print(f"  [{t}] {self.username} [{fingerprint}]: {text}")
    
    async def _dm(self, args: str):
        """Send a direct message"""
        if not self.client:
            print("  Not connected")
            return
        
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            print("  Usage: /dm <username> <message>")
            return
        
        target_username, message = parts
        
        # Find target peer to get their fingerprint
        target_fingerprint = "?"
        for pk, peer in self.client.peers.items():
            if peer.username.lower() == target_username.lower():
                target_fingerprint = peer.identity[:8] if peer.identity else pk[:8]
                break
        
        if await self.client.send_dm(target_username, message):
            t = time.strftime("%H:%M")
            print(f"  [{t}] 📤 DM to {target_username} [{target_fingerprint}]: {message}")
        else:
            print(f"  ✗ Peer '{target_username}' not found or no key")
    
    async def _reconnect(self):
        """Reconnect to relays"""
        if not self.client:
            print("  Not in a room")
            return
        
        print("  Reconnecting to relays...")
        connected = await self.client.reconnect()
        if connected > 0:
            print(f"  ✓ Reconnected ({connected} relays)")
        else:
            print("  ✗ Failed to reconnect")
    
    def _on_message(self, sender_pk: str, sender: str, text: str, ts: float, msg_id: str):
        msg = Message(
            id=msg_id,
            room=self.current_room or '',
            sender_id=sender_pk[:16],
            sender_name=sender,
            content=text,
            timestamp=ts
        )
        self.storage.save_message(msg)
        
        # Get fingerprint from peer
        fingerprint = sender_pk[:8]
        if self.client and sender_pk in self.client.peers:
            peer = self.client.peers[sender_pk]
            fingerprint = peer.identity[:8] if peer.identity else sender_pk[:8]
        
        t = time.strftime("%H:%M", time.localtime(ts / 1000))
        print(f"\r  [{t}] {sender} [{fingerprint}]: {text}")
        
        # Sound notification - check for mention first
        if self.username.lower() in text.lower():
            beep_mention()
        else:
            beep_message()
        
        prompt = f"[{self.current_room}] > " if self.current_room else "> "
        print(prompt, end='', flush=True)
    
    def _on_peer_join(self, nostr_pk: str):
        print(f"\r  + Peer: {nostr_pk[:16]}...")
    
    def _on_key_exchange(self, nostr_pk: str, username: str, ping_id: str):
        fingerprint = ping_id[:8] if ping_id else nostr_pk[:8]
        print(f"\r  🔑 {username} [{fingerprint}]")
    
    def _on_leave(self, nostr_pk: str, username: str):
        # Get fingerprint
        fingerprint = nostr_pk[:8]
        if self.client and nostr_pk in self.client.peers:
            peer = self.client.peers[nostr_pk]
            fingerprint = peer.identity[:8] if peer.identity else nostr_pk[:8]
        print(f"\r  ← {username} [{fingerprint}] left")
        prompt = f"[{self.current_room}] > " if self.current_room else "> "
        print(prompt, end='', flush=True)
    
    def _on_dm(self, sender_pk: str, sender: str, text: str, ts: float, msg_id: str):
        # Get fingerprint from peer
        fingerprint = sender_pk[:8]
        if self.client and sender_pk in self.client.peers:
            peer = self.client.peers[sender_pk]
            fingerprint = peer.identity[:8] if peer.identity else sender_pk[:8]
        
        t = time.strftime("%H:%M", time.localtime(ts / 1000))
        print(f"\r  [{t}] 📩 DM from {sender} [{fingerprint}]: {text}")
        
        # Sound notification for DM (double beep)
        beep_dm()
        
        prompt = f"[{self.current_room}] > " if self.current_room else "> "
        print(prompt, end='', flush=True)
    
    def _printsession(self):
        """Print current encryption keys"""
        import base64
        
        print(f"\n  ═══ ENCRYPTION KEYS ═══")
        print(f"  Ping ID:       {self.identity.id}")
        print(f"  Nostr Pubkey:  {self.identity.hex_pubkey[:32]}...")
        print(f"  Nostr npub:    {self.identity.npub[:32]}...")
        print(f"  X25519 Pubkey: {base64.b64encode(self.identity.encryption_keys.pub_bytes()).decode()[:32]}...")
        print(f"  Created:       {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.identity.created_at / 1000))}")
        
        # Show peer keys
        if self.client and self.client.peers:
            print(f"\n  Peer Keys:")
            for pk, peer in self.client.peers.items():
                if peer.encryption_pubkey:
                    peer_key = base64.b64encode(peer.encryption_pubkey.public_bytes_raw()).decode()[:16]
                    print(f"    🔑 {peer.username} [{peer.identity[:8] if peer.identity else pk[:8]}]: {peer_key}...")
                else:
                    print(f"    ⏳ {peer.username}: no key yet")
        print()
    
    def _invite(self):
        """Generate an invite code for the current room"""
        if not self.current_room:
            print("  Not in a room. Join a room first.")
            return
        
        # Generate invite code
        invite_code = encode_invite(self.current_room, self.current_password)
        
        print(f"\n  ═══ ROOM INVITE ═══")
        print(f"  Room: {self.current_room}" + (" 🔒" if self.current_password else ""))
        print(f"\n  Invite Code:")
        print(f"    {invite_code}")
        print(f"\n  CLI Usage:")
        print(f"    python ping_nostr.py --invite {invite_code}")
        print(f"    python ping_nostr.py -i {invite_code}")
        
        # Generate QR code if available
        qr = generate_qr_code(invite_code, small=True)
        if qr:
            print(f"\n  QR Code:")
            print(qr)
        else:
            print(f"\n  (Install 'qrcode' for QR code: pip install qrcode)")
        
        print()
    
    def _peers(self):
        if not self.client or not self.client.peers:
            print("  No peers")
            return
        
        print(f"\n  Peers ({len(self.client.peers)}):")
        for pk, peer in self.client.peers.items():
            key = "🔑" if peer.encryption_pubkey else "⏳"
            name = peer.username or "unknown"
            fingerprint = peer.identity[:8] if peer.identity else pk[:8]
            print(f"    {key} {name} [{fingerprint}]")
        print()
    
    def _relays(self):
        if not self.client:
            print("  Not connected")
            return
        
        print(f"\n  Relays:")
        for relay in self.client.relays:
            status = "✓" if relay.connected else "✗"
            print(f"    {status} {relay.url}")
        print()
    
    def _info(self):
        peers = len(self.client.peers) if self.client else 0
        keys = sum(1 for p in self.client.peers.values() if p.encryption_pubkey) if self.client else 0
        relays = len([r for r in self.client.relays if r.connected]) if self.client else 0
        
        # Room info with lock indicator
        if self.current_room:
            room_display = f"{self.current_room} 🔒" if self.current_password else self.current_room
        else:
            room_display = "None"
        
        print(f"\n  Ping ID:   {self.identity.id}")
        print(f"  Username:  {self.username}")
        print(f"  Nostr:     {self.identity.npub}")
        print(f"  Room:      {room_display}")
        print(f"  Peers:     {peers} ({keys} with keys)")
        print(f"  Relays:    {relays} connected\n")
    
    def _clear(self):
        """Clear the terminal screen"""
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
        self._banner()
        if self.current_room:
            print(f"  Room: {self.current_room}\n")
    
    def _color(self, args: str):
        """Set terminal foreground and background colors, or apply a theme"""
        parts = args.lower().split()
        
        if not parts or parts[0] in ('help', '?'):
            self._color_help()
            return
        
        if parts[0] == 'reset':
            print(reset_terminal_color(), end='', flush=True)
            print("  ✓ Colors reset to default")
            return
        
        if parts[0] == 'list':
            self._color_list()
            return
        
        if parts[0] == 'themes':
            self._color_themes()
            return
        
        # Check if it's a theme name
        if len(parts) == 1 and parts[0] in THEMES:
            theme = parts[0]
            if apply_theme(theme):
                bg, fg = THEMES[theme]
                if bg and fg:
                    print(f"  ✓ Theme '{theme}' applied (bg={bg}, fg={fg})")
                else:
                    print(f"  ✓ Theme '{theme}' applied (reset to default)")
                return
        
        # Parse bg and fg
        bg = None
        fg = None
        
        if len(parts) == 1:
            # Single argument - check if it's a color (foreground)
            if parts[0] in COLORS:
                fg = parts[0]
            else:
                print(f"  Unknown color or theme: {parts[0]}")
                print(f"  Use /color list or /color themes")
                return
        elif len(parts) >= 2:
            bg = parts[0] if parts[0] != '-' else None
            fg = parts[1] if parts[1] != '-' else None
        
        # Validate colors
        if bg and bg not in COLORS:
            print(f"  Unknown background color: {bg}")
            print(f"  Use /color list to see available colors")
            return
        
        if fg and fg not in COLORS:
            print(f"  Unknown foreground color: {fg}")
            print(f"  Use /color list to see available colors")
            return
        
        # Apply colors
        apply_terminal_color(bg, fg)
        
        # Show confirmation
        bg_name = bg or "default"
        fg_name = fg or "default"
        print(f"  ✓ Color set: bg={bg_name}, fg={fg_name}")
    
    def _color_help(self):
        """Show color command help"""
        print("""
  Usage: /color <theme>
         /color <bg> <fg>
         /color <fg>
         /color themes
         /color list
         /color reset

  Themes:
    /color matrix         - Green on black (hacker style)
    /color tron           - Cyan on black
    /color classic        - White on blue (IBM style)
    /color amber          - Yellow on black (CRT monitor)
    /color light          - Black on light blue

  Custom:
    /color blue white     - Blue background, white text
    /color black lgreen   - Black background, light green text
    /color - cyan         - Keep background, cyan text
    /color green          - Green text (foreground only)
    /color reset          - Reset to terminal defaults

  Use '-' to keep current bg or fg color.
  Use '/color themes' to see all available themes.
""")
    
    def _color_themes(self):
        """Show available themes with preview"""
        print("\n  Available Themes:\n")
        
        # Group themes (skip aliases)
        main_themes = [
            ("matrix", "Matrix / Hacker"),
            ("tron", "Tron / Cyber"),
            ("classic", "Classic IBM"),
            ("amber", "Amber CRT"),
            ("coffee", "Coffee / Sepia"),
            ("light", "Light mode"),
            ("ocean", "Ocean"),
            ("sunset", "Sunset / Fire"),
            ("grape", "Grape / Purple"),
            ("snow", "Snow (high contrast)"),
            ("midnight", "Midnight blue"),
        ]
        
        for theme, desc in main_themes:
            bg, fg = THEMES[theme]
            bg_code = COLORS[bg][1]
            fg_code = COLORS[fg][0]
            # Show preview
            print(f"    \033[{bg_code};{fg_code}m {theme:12} \033[0m  {desc}")
        
        print(f"\n  Aliases:")
        print(f"    hacker, neo → matrix")
        print(f"    cyber → tron")
        print(f"    ibm → classic")
        print(f"    crt, retro → amber")
        print(f"    sepia, earth → coffee")
        print(f"    day → light")
        print(f"    fire → sunset")
        print(f"    purple → grape")
        print()
    
    def _color_list(self):
        """Show available colors with preview"""
        print("\n  Available Colors:\n")
        
        # Normal colors
        print("  Normal:")
        for name in ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']:
            fg_code = COLORS[name][0]
            print(f"    \033[{fg_code}m{name:12}\033[0m", end='')
        print()
        
        # Light colors
        print("\n  Light/Bright:")
        for name in ['lblack', 'lred', 'lgreen', 'lyellow', 'lblue', 'lmagenta', 'lcyan', 'lwhite']:
            fg_code = COLORS[name][0]
            print(f"    \033[{fg_code}m{name:12}\033[0m", end='')
        print()
        
        # Brown/extras
        print("\n  Brown/Extra:")
        for name in ['brown', 'lbrown', 'tan', 'orange']:
            fg_code = COLORS[name][0]
            print(f"    \033[{fg_code}m{name:12}\033[0m", end='')
        print()
        
        # Aliases
        print("\n  Aliases: gray/grey (=lblack), default/none, reset")
        
        # Background preview
        print("\n  Background Preview:")
        for name in ['black', 'red', 'green', 'blue', 'magenta', 'cyan']:
            bg_code = COLORS[name][1]
            print(f"    \033[{bg_code};97m {name:^10} \033[0m", end='')
        print("\n")
    
    def _sound(self, args: str):
        """Toggle or set sound notifications"""
        global SOUND_ENABLED
        
        args = args.strip().lower()
        
        if not args:
            # Toggle
            SOUND_ENABLED = not SOUND_ENABLED
            status = "ON" if SOUND_ENABLED else "OFF"
            print(f"  🔔 Sound: {status}")
            if SOUND_ENABLED:
                beep_message()  # Play test beep
        elif args in ('on', '1', 'yes', 'true'):
            SOUND_ENABLED = True
            print(f"  🔔 Sound: ON")
            beep_message()  # Play test beep
        elif args in ('off', '0', 'no', 'false'):
            SOUND_ENABLED = False
            print(f"  🔕 Sound: OFF")
        elif args == 'test':
            print(f"  Testing sounds...")
            print(f"    Message beep:", end=' ', flush=True)
            beep_message()
            time.sleep(0.5)
            print(f"done")
            print(f"    DM beep:", end=' ', flush=True)
            beep_dm()
            time.sleep(0.5)
            print(f"done")
            print(f"    Mention beep:", end=' ', flush=True)
            beep_mention()
            print(f"done")
        else:
            print(f"  Usage: /sound [on|off|test]")
    
    def _save(self):
        """Save session, username, and settings to pingconfig.json"""
        config_path, success = Storage.export_config(
            self.identity, 
            self.username,
            room=self.current_room,
            room_password=self.initial_password
        )
        
        if success:
            print(f"\n  ✓ Saved to: {config_path}")
            print(f"    • Username:    {self.username}")
            print(f"    • Ping ID:     {self.identity.id}")
            print(f"    • Nostr npub:  {self.identity.npub[:32]}...")
            if self.current_room:
                print(f"    • Room:        {self.current_room}")
            if CURRENT_THEME:
                print(f"    • Theme:       {CURRENT_THEME}")
            elif CURRENT_BG or CURRENT_FG:
                print(f"    • Colors:      bg={CURRENT_BG or 'default'}, fg={CURRENT_FG or 'default'}")
            print(f"    • Sound:       {'on' if SOUND_ENABLED else 'off'}")
            if LEGACY_MODE:
                print(f"    • Mode:        legacy")
            elif HARDENED_MODE:
                print(f"    • Mode:        hardened")
            print(f"\n  Use --load to restore this session")
        else:
            print(f"\n  ✗ Save failed")
            print(f"    • Path: {config_path}")
        print()
    
    def _load(self):
        """Load session, username, and settings from pingconfig.json"""
        global SOUND_ENABLED, LEGACY_MODE, HARDENED_MODE
        
        identity, username, settings, error = Storage.import_config()
        
        if identity:
            self.identity = identity
            if username:
                self.username = username
            
            # Update client if connected
            if self.client:
                self.client.identity = identity
                self.client.username = self.username
            
            print(f"\n  ✓ Loaded from: {Storage.get_config_path()}")
            print(f"    • Username:    {self.username}")
            print(f"    • Ping ID:     {self.identity.id}")
            print(f"    • Nostr npub:  {self.identity.npub[:32]}...")
            
            # Apply settings if present
            if settings:
                # Sound
                SOUND_ENABLED = settings.get("sound_enabled", True)
                print(f"    • Sound:       {'on' if SOUND_ENABLED else 'off'}")
                
                # Privacy mode
                LEGACY_MODE = settings.get("legacy_mode", False)
                HARDENED_MODE = settings.get("hardened_mode", False)
                if LEGACY_MODE:
                    print(f"    • Mode:        legacy")
                elif HARDENED_MODE:
                    print(f"    • Mode:        hardened")
                
                # Theme/colors
                theme = settings.get("theme")
                bg_color = settings.get("bg_color")
                fg_color = settings.get("fg_color")
                
                if theme:
                    apply_theme(theme)
                    print(f"    • Theme:       {theme}")
                elif bg_color or fg_color:
                    apply_terminal_color(bg_color, fg_color)
                    print(f"    • Colors:      bg={bg_color or 'default'}, fg={fg_color or 'default'}")
                
                # Room info
                room = settings.get("room")
                room_password = settings.get("room_password")
                if room:
                    print(f"    • Room:        {room}")
                    self.initial_room = room
                    self.initial_password = room_password
            
            print(f"\n  ⚠️  Rejoin room to use new identity")
        else:
            print(f"\n  ✗ Load failed: {error}")
        print()
    
    async def _update(self, args: str):
        """Check for updates and optionally install them"""
        args = args.lower().strip()
        
        if args == 'restore':
            # Restore from backup
            print("\n  Restoring from backup...")
            success, message = restore_backup()
            if success:
                print(f"  ✓ {message}")
                print("  Restart the application to use the restored version.")
            else:
                print(f"  ✗ {message}")
            print()
            return
        
        print(f"\n  Current version: {APP_VERSION}")
        print(f"  Update URL: {UPDATE_URL}")
        print("  Checking for updates...")
        
        # Check for updates
        update_available, remote_version, remote_content, error = check_for_updates()
        
        if remote_version is None:
            print("  ✗ Failed to check for updates")
            if error:
                print(f"  Error: {error}")
            print("\n  Troubleshooting:")
            print("    • Check your internet connection")
            print("    • Try: pip install certifi")
            print("    • The GitHub URL may be blocked on your network")
            print()
            return
        
        print(f"  Remote version:  {remote_version}")
        
        if not update_available:
            if compare_versions(APP_VERSION, remote_version) > 0:
                print("  ℹ️  You're running a newer version than the repository")
            else:
                print("  ✓ You're up to date!")
            print()
            return
        
        print(f"\n  ⬆️  Update available: {APP_VERSION} → {remote_version}")
        print(f"  Source: {UPDATE_URL}")
        
        if args == 'check':
            # Just checking, don't install
            print("\n  Run '/update' again to install, or '/update force' to skip confirmation.")
            print()
            return
        
        # Ask for confirmation unless forced
        if args != 'force':
            print()
            confirm = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("  Install update? [y/N]: ")
            )
            if confirm.lower() not in ('y', 'yes'):
                print("  Update cancelled")
                print()
                return
        
        print("\n  Downloading and installing update...")
        success, message = perform_update(remote_content)
        
        if success:
            print(f"  ✓ {message}")
            print(f"  If something goes wrong, run '/update restore' to revert.")
            
            # Prompt for restart
            print()
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("  Restart now? [Y/n]: ")
                )
                if response.strip().lower() in ('', 'y', 'yes'):
                    import os
                    script_path = str(get_script_path())
                    print(f"  Restarting...")
                    os.execv(sys.executable, [sys.executable, script_path] + sys.argv[1:])
            except (KeyboardInterrupt, EOFError):
                pass
            
            print(f"  Run 'python {Path(__file__).name}' to use the new version")
        else:
            print(f"  ✗ {message}")
        print()
    
    async def _wipe(self):
        """Wipe all local data and reset identity"""
        print("  ⚠️  This will delete ALL local data including:")
        print("      - Your identity (Ping ID and keys)")
        print("      - Chat history")
        print("      - Username")
        print()
        confirm = await asyncio.get_event_loop().run_in_executor(
            None, lambda: input("  Type 'WIPE' to confirm: ")
        )
        
        if confirm.strip() == 'WIPE':
            # Leave room first
            if self.current_room:
                await self._leave()
            
            # Delete data directory
            import shutil
            if DATA_DIR.exists():
                shutil.rmtree(DATA_DIR)
                print("  ✓ All data wiped")
            else:
                print("  No data to wipe")
            
            # Reset identity
            self.storage = Storage(self.memory_only)
            self.identity = self.storage.load_identity()
            self.username = self.storage.load_username()
            print(f"  ✓ New identity: {self.identity.id[:16]}...")
            print(f"  ✓ New username: {self.username}")
        else:
            print("  Cancelled")
    
    async def _cleanup(self):
        if self.current_room:
            await self._leave()


# ==============================================================================
# Entry Point
# ==============================================================================

def main():
    global DEBUG, LEGACY_MODE, HARDENED_MODE, SOUND_ENABLED
    parser = argparse.ArgumentParser(description='Ping - Decentralized E2E Encrypted Messenger')
    parser.add_argument('--room', '-r', help='Room to join')
    parser.add_argument('--password', '-p', help='Room password (optional)')
    parser.add_argument('--invite', '-i', help='Join via invite code')
    parser.add_argument('--username', '-u', help='Username')
    parser.add_argument('--color', '-c', help='Theme or colors: "matrix", "bg:fg", "fg" (e.g., "tron", "black:lgreen")')
    parser.add_argument('--persist', action='store_true', help='Persistent mode (save identity to ~/.ping)')
    parser.add_argument('--load', '-l', action='store_true', help='Load identity from pingconfig.json')
    parser.add_argument('--legacy', action='store_true', help='Legacy mode (compatible with old clients)')
    parser.add_argument('--hardened', action='store_true', help='Hardened mode (decoys, timing jitter)')
    parser.add_argument('--no-sound', action='store_true', help='Disable sound notifications')
    parser.add_argument('--update', action='store_true', help='Check for updates and install')
    parser.add_argument('--debug', '-d', action='store_true', help='Show debug output')
    parser.add_argument('--version', '-v', action='version', version=f'Ping {APP_VERSION}')
    args = parser.parse_args()
    
    DEBUG = args.debug
    
    # Handle --no-sound flag
    if args.no_sound:
        SOUND_ENABLED = False
    
    # Handle --update flag (run update and exit)
    if args.update:
        sys.exit(cli_update())
    
    # Handle privacy flags
    if args.legacy:
        LEGACY_MODE = True
        if DEBUG:
            print("Privacy Shield: LEGACY (disabled for compatibility)")
    elif args.hardened:
        HARDENED_MODE = True
        if DEBUG:
            print("Privacy Shield: HARDENED (full protection)")
    else:
        if DEBUG:
            print("Privacy Shield: DEFAULT (envelopes + ephemeral keys)")
    
    if DEBUG:
        print(f"Using {SECP256K1_LIB} for Nostr signatures")
    
    # Handle invite code
    room = args.room
    password = args.password
    
    if args.invite:
        invite_room, invite_password = decode_invite(args.invite)
        if invite_room:
            room = invite_room
            password = invite_password
            if DEBUG:
                print(f"Decoded invite: room={room}, password={'***' if password else 'None'}")
        else:
            print(f"Invalid invite code: {args.invite}")
            sys.exit(1)
    
    # Handle color argument
    if args.color:
        color_arg = args.color.lower()
        
        # Check if it's a theme name
        if color_arg in THEMES:
            apply_theme(color_arg)
        elif ':' in args.color:
            # Format: "bg:fg"
            parts = args.color.lower().split(':', 1)
            bg_color = parts[0] if parts[0] and parts[0] != '-' else None
            fg_color = parts[1] if len(parts) > 1 and parts[1] and parts[1] != '-' else None
            
            # Validate colors
            if bg_color and bg_color not in COLORS:
                print(f"Unknown background color: {bg_color}")
                print(f"Available colors: {', '.join(sorted(set(COLORS.keys())))}")
                print(f"Available themes: {', '.join(sorted(THEMES.keys()))}")
                sys.exit(1)
            
            if fg_color and fg_color not in COLORS:
                print(f"Unknown foreground color: {fg_color}")
                print(f"Available colors: {', '.join(sorted(set(COLORS.keys())))}")
                print(f"Available themes: {', '.join(sorted(THEMES.keys()))}")
                sys.exit(1)
            
            apply_terminal_color(bg_color, fg_color)
        elif color_arg in COLORS:
            # Single color = foreground only
            apply_terminal_color(None, color_arg)
        else:
            print(f"Unknown color or theme: {args.color}")
            print(f"Available colors: {', '.join(sorted(set(COLORS.keys())))}")
            print(f"Available themes: {', '.join(sorted(THEMES.keys()))}")
            sys.exit(1)
    
    # Determine persistence mode (default is ephemeral/memory-only)
    memory_only = not args.persist
    
    asyncio.run(PingNostrCLI(
        room=room, 
        password=password, 
        username=args.username, 
        memory_only=memory_only, 
        legacy_mode=args.legacy,
        hardened_mode=args.hardened,
        load_config=args.load
    ).run())


if __name__ == '__main__':
    main()
