import re
from urllib.parse import urlparse

def extract_url_features(url: str):
    parsed = urlparse(url)

    return {
        "having_IP": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "URL_Length": len(url),
        "Shortining_Service": 1 if any(s in url for s in ["bit.ly", "tinyurl"]) else 0,
        "having_At_Symbol": 1 if "@" in url else 0,
        "double_slash_redirecting": 1 if url.count("//") > 1 else 0,
        "Prefix_Suffix": 1 if "-" in parsed.netloc else 0,
        "having_Sub_Domain": parsed.netloc.count(".") - 1,
        "SSLfinal_State": 1 if parsed.scheme == "https" else 0,
        "Domain_registeration_length": 0,
        "Favicon": 0,
        "port": 1 if parsed.port else 0,
        "HTTPS_token": 1 if "https" in parsed.netloc else 0,
        "Request_URL": 0,
        "URL_of_Anchor": 0,
        "Links_in_tags": 0,
        "SFH": 0,
        "Submitting_to_email": 0,
        "Abnormal_URL": 0,
        "Redirect": 0,
        "on_mouseover": 0,
        "RightClick": 0,
        "popUpWidnow": 0,
        "Iframe": 0,
        "age_of_domain": 0,
        "DNSRecord": 0,
        "web_traffic": 0,
        "Page_Rank": 0,
        "Google_Index": 1,
        "Links_pointing_to_page": 0,
        "Statistical_report": 0
    }
