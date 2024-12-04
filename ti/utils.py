# utils.py
from datetime import datetime, timezone

def parse_datetime(dt_str):
    """Parse datetime string from API response"""
    try:
        return datetime.strptime(dt_str, "%a, %d %b %Y %H:%M:%S GMT")
    except:
        return None

def calculate_severity_level(score):
    """Convert numeric severity to text level"""
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"