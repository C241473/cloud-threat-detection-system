import ipaddress

def get_ip_geolocation(ip: str) -> dict:
    """
    Returns simulated Geo/IP details for a given IP address.
    In production, this would call MaxMind GeoIP or an external API like ipinfo.io.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {
                "ip": ip,
                "country": "Local Network",
                "country_code": "LOC",
                "region": "Private Subnet",
                "isp": "Internal Network / Localhost",
                "flag": "🏠"
            }
    except ValueError:
        pass

    # Deterministic mock based on IP hash for testing public IPs
    mock_locations = [
        {"country": "United States", "country_code": "US", "region": "California", "isp": "Amazon AWS", "flag": "🇺🇸"},
        {"country": "Germany", "country_code": "DE", "region": "Frankfurt", "isp": "Hetzner Online", "flag": "🇩🇪"},
        {"country": "Bangladesh", "country_code": "BD", "region": "Dhaka", "isp": "Grameenphone Ltd", "flag": "🇧🇩"},
        {"country": "Japan", "country_code": "JP", "region": "Tokyo", "isp": "NTT Communications", "flag": "🇯🇵"},
        {"country": "United Kingdom", "country_code": "GB", "region": "London", "isp": "DigitalOcean", "flag": "🇬🇧"},
    ]
    
    val = sum(ord(c) for c in ip)
    loc = mock_locations[val % len(mock_locations)]
    loc["ip"] = ip
    return loc
