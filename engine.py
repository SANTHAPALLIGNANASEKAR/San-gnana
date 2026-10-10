"""
PhishGuard AI engine — educational heuristic prototype.
This is not a trained model and its scores are not calibrated probabilities.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from PIL import Image, ImageOps

BRAND_DIR = Path(__file__).resolve().parent / "trusted_brands"
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
TRUSTED_BRANDS = {
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"],
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work", "country", "gq", "tk",
    "rest", "support", "cam", "quest", "bar", "icu"
}
TEXT_RULES = {
    "urgency": [
        r"\bimmediately\b", r"\burgent(?:ly)?\b", r"\bact now\b",
        r"\bwithin \d+ hours?\b", r"\bexpires? today\b", r"\blast warning\b",
        r"\baccount (?:will be|is being) (?:closed|suspended|locked)\b",
    ],
    "credential requests": [
        r"\bpassword\b", r"\bverify your account\b", r"\blog ?in\b",
        r"\benter your (?:credentials|otp|pin)\b", r"\bone[- ]time password\b",
        r"\bsecurity code\b", r"\bconfirm your identity\b",
    ],
    "financial pressure": [
        r"\bwire transfer\b", r"\bpay immediately\b", r"\bpayment required\b",
        r"\bclaim your prize\b", r"\bgift card\b", r"\bbank account\b",
        r"\brefund is pending\b", r"\bcrypto(?:currency)? payment\b",
    ],
    "impersonation": [
        r"\bIT support\b", r"\bhelp ?desk\b", r"\bCEO\b", r"\badministrator\b",
        r"\bsecurity team\b", r"\byour bank\b", r"\bgovernment\b",
    ],
    "social engineering": [
        r"\bdo not tell\b", r"\bkeep this confidential\b", r"\bclick (?:here|the link)\b",
        r"\bavoid (?:suspension|termination)\b", r"\bupdate your details\b",
        r"\bwe detected unusual activity\b",
    ],
}

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 3)

def _normalise_url(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Please provide a URL.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    return value

def _is_public_hostname(hostname: str) -> bool:
    """Only permit public IP literals for network checks; reject localhost/private targets."""
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_global
    except ValueError:
        host = hostname.lower().rstrip(".")
        return host not in {"localhost"} and not host.endswith((".localhost", ".local", ".internal"))

def _registered_domain(hostname: str) -> str:
    ext = tldextract.TLDExtract(suffix_list_urls=())(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return hostname.lower()

def _brand_lookalikes(hostname: str) -> list[str]:
    findings = []
    host = hostname.lower().strip(".")
    registered = _registered_domain(host)
    for brand, domains in TRUSTED_BRANDS.items():
        if any(registered == d or registered.endswith("." + d) for d in domains):
            continue
        # Flag brand names in a different registered domain, including common typo-like forms.
        if brand in host and not any(host == d or host.endswith("." + d) for d in domains):
            findings.append(f"Hostname contains '{brand}' but is not a known {brand} domain.")
        # Simple edit-distance-free lookalike signals for obvious substitutions.
        for domain in domains:
            stem = domain.split(".")[0]
            if len(stem) >= 5 and (stem.replace("o", "0") in host or stem.replace("i", "1") in host):
                findings.append(f"Hostname may imitate the {brand} brand.")
                break
    return list(dict.fromkeys(findings))

def analyze_url(raw_url: str) -> dict:
    url = _normalise_url(raw_url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not _is_public_hostname(hostname):
        raise ValueError("Local, private, or non-public IP destinations are not analyzed.")

    score = 0
    findings = []
    if parsed.scheme != "https":
        score += 12
        findings.append("The URL does not use HTTPS.")
    if "@" in parsed.netloc:
        score += 18
        findings.append("The URL contains an @ sign in its authority section.")
    if len(url) > 100:
        score += 8
        findings.append("The URL is unusually long.")
    if len(hostname) > 45:
        score += 8
        findings.append("The hostname is unusually long.")
    if sum(ch.isdigit() for ch in hostname) >= 5:
        score += 8
        findings.append("The hostname contains many digits.")
    if hostname.count("-") >= 3:
        score += 8
        findings.append("The hostname contains several hyphens.")
    entropy = _entropy(hostname)
    if entropy >= 3.7 and len(hostname) >= 14:
        score += 8
        findings.append("The hostname has relatively high character entropy.")
    registered_domain = _registered_domain(hostname)
    suffix = tldextract.TLDExtract(suffix_list_urls=())(hostname).suffix.lower()
    if suffix in SUSPICIOUS_TLDS:
        score += 10
        findings.append(f"The .{suffix} top-level domain is sometimes used in suspicious links; this alone is not proof.")
    lookalikes = _brand_lookalikes(hostname)
    if lookalikes:
        score += min(30, 18 + 4 * (len(lookalikes) - 1))
        findings.extend(lookalikes)

    age = "Unavailable (best-effort RDAP lookup)"
    # RDAP is an optional best-effort check; never fail the scan just because it is unavailable.
    try:
        response = requests.get(
            f"https://rdap.org/domain/{registered_domain}",
            timeout=4,
            headers={"User-Agent": "PhishGuardAI-StudentPrototype/1.0"},
        )
        if response.ok:
            data = response.json()
            events = data.get("events", [])
            created = next((e.get("eventDate") for e in events if e.get("eventAction") in {"registration", "registered"}), None)
            if created:
                from datetime import datetime, timezone
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                days = max(0, (datetime.now(timezone.utc) - created_dt).days)
                age = f"About {days} days"
                if days < 30:
                    score += 15
                    findings.append("The domain appears to be less than 30 days old.")
                elif days < 180:
                    score += 7
                    findings.append("The domain appears to be less than 6 months old.")
    except Exception:
        pass

    redirects = []
    # Do not automatically follow redirects. Record only the initial URL to avoid
    # contacting arbitrary redirect targets from an untrusted input.
    try:
        response = requests.get(
            url, timeout=4, allow_redirects=False, stream=True,
            headers={"User-Agent": "PhishGuardAI-StudentPrototype/1.0"},
        )
        location = response.headers.get("Location")
        if response.is_redirect and location:
            target = urljoin(url, location)
            redirects = [url, target]
            target_host = (urlparse(target).hostname or "").lower()
            if target_host and target_host != hostname:
                score += 8
                findings.append("The server advertises a redirect to a different hostname; the destination was not followed.")
        response.close()
    except Exception:
        findings.append("Live redirect check unavailable; network or server behavior may block it.")

    if not findings:
        findings.append("No strong URL indicators were detected by the available heuristic checks.")
    return {
        "score": max(0, min(100, score)),
        "domain": registered_domain,
        "age": age,
        "entropy": entropy,
        "findings": findings,
        "redirects": redirects,
        "url": url,
    }

def analyze_text(text: str) -> dict:
    content = (text or "").strip()
    if not content:
        return {"score": 0, "categories_matched": [], "findings": ["No message text supplied."]}
    categories = []
    findings = []
    score = 0
    for category, patterns in TEXT_RULES.items():
        matches = [pattern for pattern in patterns if re.search(pattern, content, flags=re.IGNORECASE)]
        if matches:
            categories.append(category)
            score += min(22, 8 + 4 * (len(matches) - 1))
            findings.append(f"Possible {category} language detected ({len(matches)} matching signal(s)).")
    if re.search(r"https?://|www\.", content, flags=re.IGNORECASE):
        score += 5
        findings.append("The message contains a web link.")
    if not findings:
        findings.append("No strong social-engineering phrases were detected by the available rules.")
    return {
        "score": max(0, min(100, score)),
        "categories_matched": categories or ["None detected"],
        "findings": findings,
    }

def reference_image_count() -> int:
    if not BRAND_DIR.exists():
        return 0
    return sum(1 for p in BRAND_DIR.iterdir() if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS)

def _phash(image: Image.Image) -> int:
    # Compact average-hash style visual comparison; approximate, not authentication.
    image = ImageOps.grayscale(image).resize((8, 8), Image.Resampling.LANCZOS)
    pixels = list(image.getdata())
    mean = sum(pixels) / len(pixels)
    bits = 0
    for pixel in pixels:
        bits = (bits << 1) | int(pixel >= mean)
    return bits

def compare_brand_image(uploaded_file):
    if reference_image_count() == 0:
        return None, "No trusted reference images found. Add authorized PNG/JPG/WEBP files to trusted_brands/.", None
    try:
        uploaded_file.seek(0)
        with Image.open(uploaded_file) as im:
            candidate_hash = _phash(im.convert("RGB"))
    except Exception:
        return None, "The uploaded image could not be read.", None

    best_similarity = 0.0
    best_name = None
    for path in BRAND_DIR.iterdir():
        if not path.is_file() or path.suffix.lower() not in IMAGE_EXTENSIONS:
            continue
        try:
            with Image.open(path) as ref:
                ref_hash = _phash(ref.convert("RGB"))
            distance = (candidate_hash ^ ref_hash).bit_count()
            similarity = 1.0 - distance / 64.0
            if similarity > best_similarity:
                best_similarity, best_name = similarity, path.name
        except Exception:
            continue
    if best_name is None:
        return None, "No readable trusted reference images were found.", None
    percent = round(best_similarity * 100, 1)
    message = f"Closest reference: {best_name} ({percent}% broad visual similarity). Similarity does not prove authenticity."
    return percent, message, best_name

def fuse_risk(url_result: dict | None, text_result: dict | None, image_similarity: float | None) -> tuple[int, str]:
    components = []
    if url_result:
        components.append((url_result.get("score", 0), 0.55))
    if text_result:
        components.append((text_result.get("score", 0), 0.45))
    if image_similarity is not None:
        # A visual match is only a weak signal, not proof of phishing.
        if image_similarity < 65:
            components.append((25, 0.10))
        elif image_similarity >= 92:
            components.append((0, 0.05))
    if not components:
        return 0, "SAFE — NO STRONG INDICATORS FOUND"
    total_weight = sum(weight for _, weight in components)
    score = round(sum(value * weight for value, weight in components) / total_weight)
    score = max(0, min(100, score))
    if score >= 60:
        label = "HIGH RISK"
    elif score >= 30:
        label = "SUSPICIOUS"
    else:
        label = "SAFE — NO STRONG INDICATORS FOUND"
    return score, label
