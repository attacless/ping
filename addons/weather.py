#!/usr/bin/env python3
"""
Weather Addon for Ping
======================
Get current weather and forecasts for any location.

Uses Open-Meteo API (free, no API key required).

Commands:
  /weather <city>        - Get current weather for a city
  /forecast <city>       - Get 3-day forecast for a city
  
Examples:
  /weather London
  /weather "New York"
  /weather Tokyo
  /forecast Paris
"""

from __future__ import annotations

import json
import urllib.request
import urllib.parse
from typing import Optional, Dict, Any
from datetime import datetime

# When loaded by ping's addon system, PingAddon is injected into this module's namespace
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


# =============================================================================
# API Configuration
# =============================================================================

GEOCODING_URL = "https://geocoding-api.open-meteo.com/v1/search"
WEATHER_URL = "https://api.open-meteo.com/v1/forecast"

# Weather code to description and emoji mapping
WEATHER_CODES = {
    0: ("Clear sky", "☀️"),
    1: ("Mainly clear", "🌤️"),
    2: ("Partly cloudy", "⛅"),
    3: ("Overcast", "☁️"),
    45: ("Foggy", "🌫️"),
    48: ("Depositing rime fog", "🌫️"),
    51: ("Light drizzle", "🌧️"),
    53: ("Moderate drizzle", "🌧️"),
    55: ("Dense drizzle", "🌧️"),
    56: ("Light freezing drizzle", "🌨️"),
    57: ("Dense freezing drizzle", "🌨️"),
    61: ("Slight rain", "🌧️"),
    63: ("Moderate rain", "🌧️"),
    65: ("Heavy rain", "🌧️"),
    66: ("Light freezing rain", "🌨️"),
    67: ("Heavy freezing rain", "🌨️"),
    71: ("Slight snow", "🌨️"),
    73: ("Moderate snow", "🌨️"),
    75: ("Heavy snow", "❄️"),
    77: ("Snow grains", "🌨️"),
    80: ("Slight rain showers", "🌦️"),
    81: ("Moderate rain showers", "🌦️"),
    82: ("Violent rain showers", "⛈️"),
    85: ("Slight snow showers", "🌨️"),
    86: ("Heavy snow showers", "🌨️"),
    95: ("Thunderstorm", "⛈️"),
    96: ("Thunderstorm with slight hail", "⛈️"),
    99: ("Thunderstorm with heavy hail", "⛈️"),
}

# Wind direction
def get_wind_direction(degrees: float) -> str:
    """Convert wind degrees to cardinal direction."""
    directions = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
                  "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
    idx = round(degrees / 22.5) % 16
    return directions[idx]


# =============================================================================
# API Functions
# =============================================================================

def geocode_city(city: str) -> Optional[Dict[str, Any]]:
    """
    Look up city coordinates using Open-Meteo Geocoding API.
    
    Returns dict with: name, country, latitude, longitude, timezone
    """
    try:
        params = urllib.parse.urlencode({
            "name": city,
            "count": 1,
            "language": "en",
            "format": "json"
        })
        url = f"{GEOCODING_URL}?{params}"
        
        req = urllib.request.Request(url, headers={"User-Agent": "PingWeatherAddon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
        
        results = data.get("results", [])
        if not results:
            return None
        
        result = results[0]
        return {
            "name": result.get("name", city),
            "country": result.get("country", ""),
            "country_code": result.get("country_code", ""),
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "timezone": result.get("timezone", "UTC"),
            "admin1": result.get("admin1", ""),  # State/province
        }
    except Exception as e:
        return None


def get_weather(lat: float, lon: float, timezone: str = "auto") -> Optional[Dict[str, Any]]:
    """
    Get current weather and forecast from Open-Meteo API.
    
    Returns dict with current conditions and daily forecast.
    """
    try:
        params = urllib.parse.urlencode({
            "latitude": lat,
            "longitude": lon,
            "timezone": timezone,
            "current": "temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m,wind_direction_10m,is_day",
            "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,precipitation_probability_max,wind_speed_10m_max",
            "forecast_days": 4,
        })
        url = f"{WEATHER_URL}?{params}"
        
        req = urllib.request.Request(url, headers={"User-Agent": "PingWeatherAddon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
        
        return data
    except Exception as e:
        return None


# =============================================================================
# Formatting Functions
# =============================================================================

def format_current_weather(location: Dict, weather: Dict) -> list[str]:
    """Format current weather as lines for display."""
    lines = []
    
    current = weather.get("current", {})
    units = weather.get("current_units", {})
    
    # Location header
    loc_parts = [location["name"]]
    if location.get("admin1"):
        loc_parts.append(location["admin1"])
    if location.get("country"):
        loc_parts.append(location["country"])
    loc_str = ", ".join(loc_parts)
    
    # Weather code
    code = current.get("weather_code", 0)
    description, emoji = WEATHER_CODES.get(code, ("Unknown", "❓"))
    
    # Temperature
    temp = current.get("temperature_2m", 0)
    feels_like = current.get("apparent_temperature", temp)
    temp_unit = units.get("temperature_2m", "°C")
    
    # Other data
    humidity = current.get("relative_humidity_2m", 0)
    wind_speed = current.get("wind_speed_10m", 0)
    wind_dir = get_wind_direction(current.get("wind_direction_10m", 0))
    wind_unit = units.get("wind_speed_10m", "km/h")
    precip = current.get("precipitation", 0)
    precip_unit = units.get("precipitation", "mm")
    is_day = current.get("is_day", 1)
    
    # Format output
    lines.append("")
    lines.append("  ╔═══════════════════════════════════════════════╗")
    lines.append(f"  ║  {emoji} WEATHER: {loc_str[:35]:35}  ║")
    lines.append("  ╠═══════════════════════════════════════════════╣")
    lines.append(f"  ║  Conditions:  {description:30} ║")
    lines.append(f"  ║  Temperature: {temp:.1f}{temp_unit} (feels like {feels_like:.1f}{temp_unit})   ║")
    lines.append(f"  ║  Humidity:    {humidity}%                            ║")
    lines.append(f"  ║  Wind:        {wind_speed:.1f} {wind_unit} {wind_dir:4}                  ║")
    if precip > 0:
        lines.append(f"  ║  Precipitation: {precip:.1f} {precip_unit}                      ║")
    lines.append("  ╚═══════════════════════════════════════════════╝")
    lines.append("")
    
    return lines


def format_forecast(location: Dict, weather: Dict) -> list[str]:
    """Format weather forecast as lines for display."""
    lines = []
    
    daily = weather.get("daily", {})
    units = weather.get("daily_units", {})
    
    # Location header
    loc_parts = [location["name"]]
    if location.get("country"):
        loc_parts.append(location["country"])
    loc_str = ", ".join(loc_parts)
    
    dates = daily.get("time", [])
    codes = daily.get("weather_code", [])
    temp_max = daily.get("temperature_2m_max", [])
    temp_min = daily.get("temperature_2m_min", [])
    precip = daily.get("precipitation_sum", [])
    precip_prob = daily.get("precipitation_probability_max", [])
    wind_max = daily.get("wind_speed_10m_max", [])
    
    temp_unit = units.get("temperature_2m_max", "°C")
    
    lines.append("")
    lines.append("  ╔═══════════════════════════════════════════════════════════╗")
    lines.append(f"  ║  📅 FORECAST: {loc_str[:42]:42}  ║")
    lines.append("  ╠═══════════════════════════════════════════════════════════╣")
    lines.append("  ║  Date       │ Conditions      │ Temp      │ Rain │ Wind ║")
    lines.append("  ╠═══════════════════════════════════════════════════════════╣")
    
    for i in range(min(4, len(dates))):
        date_str = dates[i] if i < len(dates) else ""
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            if i == 0:
                day_name = "Today"
            elif i == 1:
                day_name = "Tomorrow"
            else:
                day_name = dt.strftime("%a %m/%d")
        except:
            day_name = date_str[:10]
        
        code = codes[i] if i < len(codes) else 0
        desc, emoji = WEATHER_CODES.get(code, ("Unknown", "❓"))
        desc_short = f"{emoji} {desc}"[:15]
        
        t_max = temp_max[i] if i < len(temp_max) else 0
        t_min = temp_min[i] if i < len(temp_min) else 0
        temp_str = f"{t_min:.0f}-{t_max:.0f}{temp_unit}"
        
        prob = precip_prob[i] if i < len(precip_prob) else 0
        rain_str = f"{prob:2}%"
        
        wind = wind_max[i] if i < len(wind_max) else 0
        wind_str = f"{wind:.0f}"
        
        lines.append(f"  ║  {day_name:10} │ {desc_short:15} │ {temp_str:9} │ {rain_str:4} │ {wind_str:4} ║")
    
    lines.append("  ╚═══════════════════════════════════════════════════════════╝")
    lines.append("")
    
    return lines


# =============================================================================
# Addon Class
# =============================================================================

class WeatherAddon(PingAddon):
    """Weather information addon for Ping."""
    
    name = "Weather"
    version = "1.0.0"
    description = "Weather forecasts via Open-Meteo"
    
    def __init__(self):
        super().__init__()
        self.commands = {
            "weather": (self.cmd_weather, "Get current weather: /weather <city>"),
            "forecast": (self.cmd_forecast, "Get forecast: /forecast <city>"),
        }
    
    async def cmd_weather(self, args: str, cli) -> None:
        """Handle /weather command."""
        city = args.strip()
        if not city:
            cli._print("  Usage: /weather <city>")
            cli._print("  Example: /weather London")
            return
        
        cli._print(f"  Looking up weather for {city}...")
        
        # Geocode city
        location = geocode_city(city)
        if not location:
            cli._print(f"  ✗ City not found: {city}")
            return
        
        # Get weather
        weather = get_weather(
            location["latitude"], 
            location["longitude"],
            location.get("timezone", "auto")
        )
        if not weather:
            cli._print(f"  ✗ Failed to fetch weather data")
            return
        
        # Display
        lines = format_current_weather(location, weather)
        for line in lines:
            cli._print(line)
    
    async def cmd_forecast(self, args: str, cli) -> None:
        """Handle /forecast command."""
        city = args.strip()
        if not city:
            cli._print("  Usage: /forecast <city>")
            cli._print("  Example: /forecast Paris")
            return
        
        cli._print(f"  Looking up forecast for {city}...")
        
        # Geocode city
        location = geocode_city(city)
        if not location:
            cli._print(f"  ✗ City not found: {city}")
            return
        
        # Get weather
        weather = get_weather(
            location["latitude"], 
            location["longitude"],
            location.get("timezone", "auto")
        )
        if not weather:
            cli._print(f"  ✗ Failed to fetch weather data")
            return
        
        # Display
        lines = format_forecast(location, weather)
        for line in lines:
            cli._print(line)


# Setup function for addon loading
def setup() -> WeatherAddon:
    """Called by addon loader to get the addon instance."""
    return WeatherAddon()


# =============================================================================
# Standalone Testing
# =============================================================================

if __name__ == "__main__":
    import sys
    
    city = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "London"
    
    print(f"Looking up: {city}")
    
    location = geocode_city(city)
    if not location:
        print(f"City not found: {city}")
        sys.exit(1)
    
    print(f"Found: {location['name']}, {location.get('country', '')}")
    print(f"Coordinates: {location['latitude']}, {location['longitude']}")
    
    weather = get_weather(location["latitude"], location["longitude"])
    if not weather:
        print("Failed to get weather")
        sys.exit(1)
    
    # Print current weather
    for line in format_current_weather(location, weather):
        print(line)
    
    # Print forecast
    for line in format_forecast(location, weather):
        print(line)
