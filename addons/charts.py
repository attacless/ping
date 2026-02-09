#!/usr/bin/env python3
"""
Charts Addon for Ping
=====================
Real-time candlestick visualization for Binance USD-M Futures.

Commands:
  /charts SYMBOL1 [SYMBOL2 ...] - Open live charts for symbols
  
Controls (in chart view):
  q       - Return to chat
  n       - Toggle focus/panes mode
  c       - Toggle candle/line mode
  f       - Toggle follow mode (auto-scroll to latest)
  ↑/↓     - Select symbol
  ←/→     - Move crosshair in time
  w/s     - Move horizontal crosshair up/down
"""

from __future__ import annotations

import asyncio
import curses
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Deque, Dict, List, Optional, Tuple, NamedTuple
import sys
from pathlib import Path

# Import base addon class from ping
# When loaded by ping's addon system, PingAddon is injected into this module's namespace
# If running standalone or PingAddon not available, use a minimal compatible class
if 'PingAddon' not in dir():
    class PingAddon:
        """Minimal PingAddon base class for standalone testing."""
        name = "Base"
        version = "1.0.0"
        description = ""
        commands = {}
        def __init__(self): self.cli = None
        def on_load(self, cli): self.cli = cli
        def on_unload(self): pass
        def on_message(self, sender, text): pass

try:
    import websockets
except ImportError:
    websockets = None


# =============================================================================
# Configuration
# =============================================================================

WS_BASE_URL = "wss://fstream.binance.com"
DEFAULT_HISTORY_SECONDS = 180
DEFAULT_SAMPLE_MS = 50
DEFAULT_TIMEFRAME = "5s"
DEFAULT_FPS = 20.0
MIN_TERMINAL_WIDTH = 80
MIN_TERMINAL_HEIGHT = 16
RECONNECT_DELAY_SECONDS = 1.0


# =============================================================================
# Enums & Data Classes
# =============================================================================

class ViewMode(Enum):
    FOCUS = auto()
    PANES = auto()


class ConnectionStatus(Enum):
    INITIALIZING = "initializing"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


@dataclass(slots=True)
class Candle:
    t_open_ms: int
    open: float
    high: float
    low: float
    close: float

    def update(self, price: float) -> None:
        self.close = price
        self.high = max(self.high, price)
        self.low = min(self.low, price)


class ParsedTrade(NamedTuple):
    symbol: str
    timestamp_ms: int
    price: float


# =============================================================================
# Utility Functions
# =============================================================================

def clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def clamp_float(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def now_ms() -> int:
    return int(time.time() * 1000)


def format_time_local(timestamp_ms: int) -> str:
    return time.strftime("%H:%M:%S", time.localtime(timestamp_ms / 1000.0))


def parse_timeframe(tf_str: str) -> int:
    tf = tf_str.strip().lower()
    multipliers = {"ms": 1, "s": 1_000, "m": 60_000, "h": 3_600_000}
    
    for suffix, mult in multipliers.items():
        if tf.endswith(suffix):
            try:
                value = float(tf[:-len(suffix)])
                return int(value * mult)
            except ValueError:
                break
    
    raise ValueError(f"Invalid timeframe '{tf_str}'")


def candle_open_time(timestamp_ms: int, timeframe_ms: int) -> int:
    return (timestamp_ms // timeframe_ms) * timeframe_ms


# =============================================================================
# Shared State
# =============================================================================

@dataclass
class SharedState:
    symbols: List[str]
    history_seconds: int
    sample_ms: int
    timeframe_ms: int
    
    lock: threading.Lock = field(default_factory=threading.Lock)
    status: ConnectionStatus = ConnectionStatus.INITIALIZING
    status_detail: str = ""
    
    last_price: Dict[str, Optional[float]] = field(default_factory=dict)
    last_trade_time: Dict[str, float] = field(default_factory=dict)
    candles: Dict[str, Deque[Candle]] = field(default_factory=dict)
    session_min: Dict[str, Optional[float]] = field(default_factory=dict)
    session_max: Dict[str, Optional[float]] = field(default_factory=dict)
    _last_sample_ms: Dict[str, int] = field(default_factory=dict)
    
    view_mode: ViewMode = ViewMode.PANES
    chart_mode: str = "line"
    selected_idx: int = 0
    scroll_offset: int = 0
    follow_mode: bool = True
    cursor_slot: int = 0
    cursor_y_frac: float = 0.5
    
    running: bool = True
    
    def __post_init__(self) -> None:
        self.symbols = [s.upper() for s in self.symbols]
        candles_needed = (self.history_seconds * 1000) // max(1, self.timeframe_ms)
        capacity = max(200, candles_needed + 50)
        
        for sym in self.symbols:
            self.last_price[sym] = None
            self.last_trade_time[sym] = 0.0
            self.candles[sym] = deque(maxlen=capacity)
            self.session_min[sym] = None
            self.session_max[sym] = None
            self._last_sample_ms[sym] = 0
    
    def get_status_string(self) -> str:
        base = self.status.value
        if self.status_detail:
            return f"{base}: {self.status_detail}"
        return base


# =============================================================================
# WebSocket Data Feed
# =============================================================================

def build_stream_url(symbols: List[str]) -> str:
    streams = "/".join(f"{s.lower()}@aggTrade" for s in symbols)
    return f"{WS_BASE_URL}/stream?streams={streams}"


def parse_aggtrade(message: str) -> Optional[ParsedTrade]:
    try:
        obj = json.loads(message)
        payload = obj.get("data", obj)
        
        symbol = payload.get("s")
        timestamp = payload.get("T")
        price = payload.get("p")
        
        if not all((symbol, timestamp, price)):
            return None
        
        return ParsedTrade(symbol, int(timestamp), float(price))
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def update_candles(state: SharedState, trade: ParsedTrade) -> None:
    sym = trade.symbol
    ts = trade.timestamp_ms
    price = trade.price
    
    with state.lock:
        if state.sample_ms > 0:
            last = state._last_sample_ms.get(sym, 0)
            if ts - last < state.sample_ms:
                return
            state._last_sample_ms[sym] = ts
        
        state.last_price[sym] = price
        state.last_trade_time[sym] = time.time()
        
        if state.session_min[sym] is None or price < state.session_min[sym]:
            state.session_min[sym] = price
        if state.session_max[sym] is None or price > state.session_max[sym]:
            state.session_max[sym] = price
        
        candle_t = candle_open_time(ts, state.timeframe_ms)
        candle_list = state.candles[sym]
        
        if candle_list and candle_list[-1].t_open_ms == candle_t:
            candle_list[-1].update(price)
        else:
            new_candle = Candle(t_open_ms=candle_t, open=price, high=price, low=price, close=price)
            candle_list.append(new_candle)


async def websocket_loop(state: SharedState) -> None:
    url = build_stream_url(state.symbols)
    
    while state.running:
        try:
            with state.lock:
                state.status = ConnectionStatus.CONNECTING
                state.status_detail = ""
            
            async with websockets.connect(url, ping_interval=20, ping_timeout=10) as ws:
                with state.lock:
                    state.status = ConnectionStatus.CONNECTED
                
                async for message in ws:
                    if not state.running:
                        break
                    trade = parse_aggtrade(message)
                    if trade:
                        update_candles(state, trade)
        
        except Exception as e:
            with state.lock:
                state.status = ConnectionStatus.RECONNECTING
                state.status_detail = str(e)[:40]
        
        if state.running:
            await asyncio.sleep(RECONNECT_DELAY_SECONDS)


def start_websocket_thread(state: SharedState) -> threading.Thread:
    def run_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(websocket_loop(state))
        finally:
            loop.close()
    
    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()
    return thread


# =============================================================================
# Rendering
# =============================================================================

@dataclass
class RenderResult:
    candle_count: int = 0
    window_min: Optional[float] = None
    window_max: Optional[float] = None
    candle_at_cursor: Optional[Candle] = None
    cursor_time: Optional[int] = None
    cursor_price: Optional[float] = None


def safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    try:
        height, width = win.getmaxyx()
        if 0 <= y < height and 0 <= x < width:
            max_len = width - x - 1
            if max_len > 0:
                win.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass


def safe_hline(win, y: int, x: int, ch: int, length: int, attr: int = 0) -> None:
    try:
        height, width = win.getmaxyx()
        if 0 <= y < height and 0 <= x < width:
            actual_len = min(length, width - x - 1)
            if actual_len > 0:
                win.hline(y, x, ch, actual_len, attr)
    except curses.error:
        pass


def init_color_pairs(symbols: List[str]) -> Dict[str, int]:
    if not curses.has_colors():
        return {}
    
    colors = [curses.COLOR_CYAN, curses.COLOR_GREEN, curses.COLOR_YELLOW, 
              curses.COLOR_MAGENTA, curses.COLOR_WHITE, curses.COLOR_RED]
    
    result = {}
    for i, sym in enumerate(symbols):
        pair_id = i + 1
        fg = colors[i % len(colors)]
        try:
            curses.init_pair(pair_id, fg, -1)
            result[sym] = pair_id
        except curses.error:
            pass
    
    return result


def render_candles(
    win,
    candles: List[Candle],
    t0: int, t1: int,
    timeframe_ms: int,
    x0: int, x1: int,
    y0: int, y1: int,
    color_attr: int,
    cursor_slot: Optional[int] = None,
    cursor_y: Optional[int] = None,
    draw_crosshair: bool = False,
    chart_mode: str = "line",
) -> RenderResult:
    result = RenderResult()
    
    chart_width = x1 - x0 + 1
    chart_height = y1 - y0 + 1
    if chart_width < 2 or chart_height < 2:
        return result
    
    slots = max(1, (t1 - t0) // timeframe_ms)
    
    visible = [c for c in candles if t0 <= c.t_open_ms < t1]
    result.candle_count = len(visible)
    
    if not visible:
        return result
    
    all_prices = []
    for c in visible:
        all_prices.extend([c.high, c.low])
    
    if not all_prices:
        return result
    
    p_min = min(all_prices)
    p_max = max(all_prices)
    result.window_min = p_min
    result.window_max = p_max
    
    price_range = p_max - p_min
    if price_range < 1e-12:
        price_range = p_max * 0.001 if p_max > 0 else 1.0
    
    def price_to_y(p: float) -> int:
        frac = (p - p_min) / price_range
        row = int((1.0 - frac) * (chart_height - 1))
        return clamp(y0 + row, y0, y1)
    
    def slot_to_x(slot: int) -> int:
        if slots <= 1:
            return x0
        frac = slot / (slots - 1) if slots > 1 else 0
        col = int(frac * (chart_width - 1))
        return clamp(x0 + col, x0, x1)
    
    # Render candles/lines - track rendered x positions to avoid overlap
    rendered_x = {}  # x -> candle (keep latest candle for each x position)
    
    for c in visible:
        slot = (c.t_open_ms - t0) // timeframe_ms
        cx = slot_to_x(slot)
        # Keep the most recent candle for each x position
        if cx not in rendered_x or c.t_open_ms > rendered_x[cx].t_open_ms:
            rendered_x[cx] = c
    
    # Now render unique positions
    for cx, c in rendered_x.items():
        if chart_mode == "candle":
            y_high = price_to_y(c.high)
            y_low = price_to_y(c.low)
            y_open = price_to_y(c.open)
            y_close = price_to_y(c.close)
            
            # Wick
            for y in range(min(y_high, y_low), max(y_high, y_low) + 1):
                safe_addstr(win, y, cx, "│", color_attr | curses.A_DIM)
            
            # Body
            body_top = min(y_open, y_close)
            body_bot = max(y_open, y_close)
            bull = c.close >= c.open
            body_char = "█" if bull else "░"
            for y in range(body_top, body_bot + 1):
                safe_addstr(win, y, cx, body_char, color_attr)
        else:
            # Line mode - plot close price
            y = price_to_y(c.close)
            safe_addstr(win, y, cx, "●", color_attr)
    
    # Crosshair
    if draw_crosshair and cursor_slot is not None and cursor_y is not None:
        cx = slot_to_x(cursor_slot)
        
        # Vertical line
        for y in range(y0, y1 + 1):
            if y != cursor_y:
                try:
                    ch = win.inch(y, cx) & 0xFF
                    if ch == ord(' '):
                        safe_addstr(win, y, cx, "┊", curses.A_DIM)
                except:
                    pass
        
        # Horizontal line
        for x in range(x0, x1 + 1):
            if x != cx:
                try:
                    ch = win.inch(cursor_y, x) & 0xFF
                    if ch == ord(' '):
                        safe_addstr(win, cursor_y, x, "┈", curses.A_DIM)
                except:
                    pass
        
        # Crosshair center
        safe_addstr(win, cursor_y, cx, "╋", curses.A_BOLD)
        
        # Find candle at cursor
        cursor_time = t0 + cursor_slot * timeframe_ms
        result.cursor_time = cursor_time
        
        for c in visible:
            if c.t_open_ms == candle_open_time(cursor_time, timeframe_ms):
                result.candle_at_cursor = c
                break
        
        # Calculate price at cursor Y
        y_frac = (cursor_y - y0) / max(1, chart_height - 1)
        result.cursor_price = p_max - y_frac * price_range
    
    return result


def format_ohlc_tooltip(candle: Optional[Candle], cursor_time: Optional[int], cursor_price: Optional[float]) -> str:
    parts = []
    if cursor_time:
        parts.append(f"T={format_time_local(cursor_time)}")
    if cursor_price is not None:
        parts.append(f"P={cursor_price:.6g}")
    if candle:
        parts.append(f"O={candle.open:.6g} H={candle.high:.6g} L={candle.low:.6g} C={candle.close:.6g}")
    return " | ".join(parts) if parts else "(no data)"


def render_timeline(win, axis_y: int, label_y: int, x0: int, x1: int, t0: int, t1: int) -> None:
    safe_hline(win, axis_y, x0, ord('─'), x1 - x0 + 1, curses.A_DIM)
    
    safe_addstr(win, label_y, x0, format_time_local(t0), curses.A_DIM)
    
    end_label = format_time_local(t1)
    safe_addstr(win, label_y, max(x0, x1 - len(end_label)), end_label, curses.A_DIM)


def render_frame(win, state: SharedState, sym_to_pair: Dict[str, int]) -> None:
    win.erase()
    height, width = win.getmaxyx()
    
    if width < MIN_TERMINAL_WIDTH or height < MIN_TERMINAL_HEIGHT:
        msg = f"Terminal too small ({width}x{height}). Need {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT}"
        safe_addstr(win, height // 2, max(0, (width - len(msg)) // 2), msg)
        win.refresh()
        return
    
    with state.lock:
        symbols = list(state.symbols)
        selected_idx = state.selected_idx
        view_mode = state.view_mode
        chart_mode = state.chart_mode
        follow_mode = state.follow_mode
        cursor_slot = state.cursor_slot
        cursor_y_frac = state.cursor_y_frac
        timeframe_ms = state.timeframe_ms
        history_seconds = state.history_seconds
        status_str = state.get_status_string()
        
        last_price = dict(state.last_price)
        last_trade_time = dict(state.last_trade_time)
        session_min = dict(state.session_min)
        session_max = dict(state.session_max)
        candles_snapshot = {sym: list(state.candles[sym]) for sym in symbols}
    
    now_s = time.time()
    t1 = now_ms()
    t0 = t1 - history_seconds * 1000
    
    if follow_mode:
        slots = max(2, int((history_seconds * 1000) // timeframe_ms) + 1)
        cursor_slot = slots - 1
    
    # Header
    mode_str = "FOCUS" if view_mode == ViewMode.FOCUS else "PANES"
    follow_str = "FOLLOW" if follow_mode else "MANUAL"
    header = f" Charts | {mode_str} | {chart_mode.upper()} | {follow_str} | {status_str} | q:quit n:mode c:chart f:follow"
    safe_addstr(win, 0, 0, header[:width - 1], curses.A_REVERSE)
    
    top_y = 1
    footer_y = height - 1
    label_y = footer_y - 1
    axis_y = label_y - 1
    bottom_y = axis_y - 1
    
    usable_height = bottom_y - top_y + 1
    if usable_height < 4:
        win.refresh()
        return
    
    if view_mode == ViewMode.FOCUS:
        sym = symbols[selected_idx]
        visible_symbols = [sym]
        scroll_offset = 0
    else:
        visible_symbols = symbols
        scroll_offset = 0
    
    min_panel_height = 6
    panel_height = max(min_panel_height, usable_height // max(1, len(visible_symbols)))
    
    x0, x1 = 1, width - 2
    
    selected_result: Optional[RenderResult] = None
    
    y = top_y
    for i, sym in enumerate(visible_symbols):
        y0_panel = y
        y1_panel = min(bottom_y, y0_panel + panel_height - 1)
        if y1_panel <= y0_panel:
            break
        
        is_selected = (scroll_offset + i) == selected_idx
        pair = sym_to_pair.get(sym, 0)
        color_attr = curses.color_pair(pair) if pair and curses.has_colors() else 0
        attr = color_attr | (curses.A_REVERSE if is_selected else 0)
        
        lp = last_price.get(sym)
        age = (now_s - last_trade_time.get(sym, 0.0)) if last_trade_time.get(sym) else 999.0
        lp_str = "?" if lp is None else f"{lp:.6f}"
        
        panel_header = f"{sym:<12} Last={lp_str:<14} Age={age:5.1f}s"
        safe_addstr(win, y0_panel, x0, panel_header[:x1 - x0 + 1], attr)
        
        chart_y0 = y0_panel + 1
        chart_y1 = y1_panel
        
        if (chart_y1 - chart_y0 + 1) >= 4:
            cross_y = chart_y0 + int(cursor_y_frac * max(1, chart_y1 - chart_y0)) if is_selected else None
            
            result = render_candles(
                win, candles_snapshot.get(sym, []),
                t0, t1, timeframe_ms,
                x0, x1, chart_y0, chart_y1,
                color_attr,
                cursor_slot=cursor_slot if is_selected else None,
                cursor_y=cross_y,
                draw_crosshair=is_selected,
                chart_mode=chart_mode,
            )
            
            if (x1 - x0) >= 70 and result.window_min is not None:
                label_x = max(x0, x1 - 26)
                safe_addstr(win, chart_y0, label_x, f"WH:{result.window_max:.5g}"[:26], color_attr | curses.A_DIM)
                safe_addstr(win, chart_y1, label_x, f"WL:{result.window_min:.5g}"[:26], color_attr | curses.A_DIM)
            
            if is_selected:
                selected_result = result
        
        if y1_panel + 1 <= bottom_y:
            safe_hline(win, y1_panel + 1, 0, ord('-'), width, curses.A_DIM)
        
        y = y1_panel + 2
        if y > bottom_y:
            break
    
    render_timeline(win, axis_y, label_y, x0, x1, t0, t1)
    
    if selected_result:
        tooltip = f"{symbols[selected_idx]} | Candles: {selected_result.candle_count} | " + format_ohlc_tooltip(
            selected_result.candle_at_cursor, selected_result.cursor_time, selected_result.cursor_price
        )
    else:
        tooltip = f"{symbols[selected_idx]} | (no data)"
    safe_addstr(win, footer_y, 1, tooltip[:width - 2])
    
    win.refresh()


def handle_input(key: int, state: SharedState) -> bool:
    if key in (ord('q'), ord('Q')):
        return False
    
    with state.lock:
        slots = max(2, int((state.history_seconds * 1000) // state.timeframe_ms) + 1)
        
        if key in (ord('n'), ord('N')):
            state.view_mode = ViewMode.FOCUS if state.view_mode == ViewMode.PANES else ViewMode.PANES
        
        elif key in (ord('c'), ord('C')):
            state.chart_mode = "candle" if state.chart_mode == "line" else "line"
        
        elif key in (ord('f'), ord('F')):
            state.follow_mode = not state.follow_mode
        
        elif key == curses.KEY_UP:
            state.selected_idx = (state.selected_idx - 1) % len(state.symbols)
        
        elif key == curses.KEY_DOWN:
            state.selected_idx = (state.selected_idx + 1) % len(state.symbols)
        
        elif key == curses.KEY_LEFT:
            state.follow_mode = False
            state.cursor_slot = max(0, state.cursor_slot - 1)
        
        elif key == curses.KEY_RIGHT:
            state.follow_mode = False
            state.cursor_slot = min(slots - 1, state.cursor_slot + 1)
        
        elif key in (ord('w'), ord('W')):
            state.cursor_y_frac = clamp_float(state.cursor_y_frac - 0.03, 0.0, 1.0)
        
        elif key in (ord('s'), ord('S')):
            state.cursor_y_frac = clamp_float(state.cursor_y_frac + 0.03, 0.0, 1.0)
    
    return True


# =============================================================================
# Main Chart Function (called from ping)
# =============================================================================

def run_charts(
    stdscr,
    symbols: List[str],
    history_seconds: int = DEFAULT_HISTORY_SECONDS,
    sample_ms: int = DEFAULT_SAMPLE_MS,
    timeframe_ms: int = 5000,  # 5s default
) -> None:
    """Run the charts UI (blocking, returns when user presses q)."""
    
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    
    state = SharedState(
        symbols=symbols,
        history_seconds=history_seconds,
        sample_ms=sample_ms,
        timeframe_ms=timeframe_ms,
    )
    
    sym_to_pair = init_color_pairs(state.symbols)
    
    # Start WebSocket feed
    ws_thread = start_websocket_thread(state)
    
    # Render loop
    frame_interval = 1.0 / DEFAULT_FPS
    last_render = 0.0
    
    while state.running:
        now = time.time()
        
        if now - last_render >= frame_interval:
            render_frame(stdscr, state, sym_to_pair)
            last_render = now
        
        key = stdscr.getch()
        if key == -1:
            time.sleep(0.002)
            continue
        
        if key == curses.KEY_RESIZE:
            continue
        
        if not handle_input(key, state):
            state.running = False
            break
    
    # Cleanup
    state.running = False


# =============================================================================
# Addon Class
# =============================================================================

class ChartsAddon(PingAddon):
    """Live cryptocurrency charts addon for Ping."""
    
    name = "Charts"
    version = "1.1.0"
    description = "Live Binance futures candlestick charts"
    
    def __init__(self):
        super().__init__()
        self.commands = {
            "charts": (self.cmd_charts, "Open live charts: /charts [time] SYMBOL1 [SYMBOL2 ...]"),
        }
    
    async def cmd_charts(self, args: str, cli) -> None:
        """Handle /charts command."""
        if websockets is None:
            cli._print("  ✗ Charts addon requires websockets: pip install websockets")
            return
        
        parts = args.upper().split()
        if not parts:
            cli._print("  Usage: /charts [time] SYMBOL1 [SYMBOL2 ...]")
            cli._print("  ")
            cli._print("  Time window (optional): 1m, 3m, 5m, 10m, 15m, 30m (default: 3m)")
            cli._print("  ")
            cli._print("  Examples:")
            cli._print("    /charts BTCUSDT")
            cli._print("    /charts 5m BTCUSDT ETHUSDT")
            cli._print("    /charts 10m SOLUSDT")
            return
        
        # Check if first arg is a time window
        history_seconds = DEFAULT_HISTORY_SECONDS  # 180s = 3m
        time_windows = {
            "1M": 60, "2M": 120, "3M": 180, "5M": 300, 
            "10M": 600, "15M": 900, "30M": 1800, "1H": 3600
        }
        
        if parts[0] in time_windows:
            history_seconds = time_windows[parts[0]]
            parts = parts[1:]  # Remove time arg from symbols
        
        symbols = parts
        if not symbols:
            cli._print("  ✗ No symbols specified")
            return
        
        # Validate symbols (basic check)
        for sym in symbols:
            if not sym.endswith("USDT") and not sym.endswith("BUSD"):
                cli._print(f"  ⚠ Warning: {sym} may not be a valid futures pair")
        
        cli._print(f"  Opening charts for: {' '.join(symbols)} ({history_seconds}s window)")
        cli._print("  Press 'q' to return to chat...")
        
        # Need to temporarily take over the curses screen
        try:
            # Get the curses UI and stdscr
            from __main__ import CURSES_UI
            
            if CURSES_UI and CURSES_UI.stdscr:
                stdscr = CURSES_UI.stdscr
                
                # Run charts (blocking)
                run_charts(stdscr, symbols, history_seconds=history_seconds)
                
                # Restore ping UI - must reset colors first
                curses.start_color()
                curses.use_default_colors()
                # Reset to default color pair
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
                
                cli._print("  Returned from charts view")
            else:
                cli._print("  ✗ Charts requires curses UI mode")
        except Exception as e:
            cli._print(f"  ✗ Error running charts: {e}")


# Setup function for addon loading
def setup() -> ChartsAddon:
    """Called by addon loader to get the addon instance."""
    return ChartsAddon()


# =============================================================================
# Standalone Mode
# =============================================================================

def run_standalone():
    """Run charts in standalone mode."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Live Binance Futures candlestick charts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s BTCUSDT
  %(prog)s BTCUSDT ETHUSDT SOLUSDT
  %(prog)s -t 5m BTCUSDT
  %(prog)s -t 10m -f 1s BTCUSDT ETHUSDT

Controls:
  q       - Quit
  n       - Toggle focus/panes mode
  c       - Toggle candle/line mode
  f       - Toggle follow mode (auto-scroll)
  ↑/↓     - Select symbol
  ←/→     - Move crosshair in time
  w/s     - Move crosshair up/down
        """
    )
    
    parser.add_argument("symbols", nargs="+", metavar="SYMBOL",
                        help="Trading pairs (e.g., BTCUSDT ETHUSDT)")
    parser.add_argument("-t", "--time", dest="history", default="3m",
                        choices=["1m", "2m", "3m", "5m", "10m", "15m", "30m", "1h"],
                        help="Time window (default: 3m)")
    parser.add_argument("-f", "--timeframe", default="5s",
                        help="Candle timeframe (default: 5s)")
    parser.add_argument("-s", "--sample", type=int, default=50,
                        help="Sample rate in ms (default: 50)")
    
    args = parser.parse_args()
    
    # Check websockets
    if websockets is None:
        print("✗ Missing: pip install websockets")
        return
    
    # Parse time window
    time_windows = {
        "1m": 60, "2m": 120, "3m": 180, "5m": 300,
        "10m": 600, "15m": 900, "30m": 1800, "1h": 3600
    }
    history_seconds = time_windows.get(args.history, 180)
    
    # Parse timeframe
    try:
        timeframe_ms = parse_timeframe(args.timeframe)
    except ValueError as e:
        print(f"✗ Invalid timeframe: {e}")
        return
    
    # Validate symbols
    symbols = [s.upper() for s in args.symbols]
    for sym in symbols:
        if not sym.endswith(("USDT", "BUSD")):
            print(f"⚠ Warning: {sym} may not be a valid futures pair")
    
    print(f"Charts: {' '.join(symbols)}")
    print(f"Window: {args.history} | Timeframe: {args.timeframe}")
    print("Press 'q' to quit")
    print()
    
    # Run with curses
    def main(stdscr):
        run_charts(
            stdscr, 
            symbols,
            history_seconds=history_seconds,
            sample_ms=args.sample,
            timeframe_ms=timeframe_ms
        )
    
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
    finally:
        # Reset terminal
        try:
            import os
            os.system('stty sane 2>/dev/null')
        except:
            pass
    
    print("\nCharts closed.")


if __name__ == "__main__":
    run_standalone()
