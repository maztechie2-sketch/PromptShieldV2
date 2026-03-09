"""
PromptShield - Layer 1: Deterministic Gatekeeper
All regex/pattern logic lives here. Swap in new detectors easily.
"""

import re
import base64
import html
from dataclasses import dataclass, field
from typing import List

@dataclass
class Layer1Result:
    passed: bool
    confidence: int  # 0-100
    hits: List[str]
    types: dict
    decoded_content: str

PATTERNS = {
    "direct": [
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"forget\s+(your\s+)?(previous\s+)?(instructions?|rules?|training)",
        r"you\s+are\s+now\s+(a\s+)?(different|new|another|evil|hacker|free|unrestricted)",
        r"override\s+(system|instructions?|prompt)",
        r"new\s+instructions?\s*:",
        r"disregard\s+(all\s+)?(previous\s+|your\s+)?(instructions?|rules?)",
        r"act\s+as\s+if\s+you\s+(have\s+no|don'?t\s+have)",
        r"developer\s+mode",
        r"DAN\s+mode|do\s+anything\s+now",
        r"jailbreak",
        r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(different|evil|unrestricted)",
    ],
    "indirect": [
        r"mandatory\s+(security\s+)?audit",
        r"compliance\s+team\s+requires?",
        r"hidden\s+instruction",
        r"system\s+override",
        r"reveal\s+(your|the)\s+system\s+prompt",
        r"forward\s+.{0,60}(to\s+)?[\w.\-]+@[\w.\-]+",
        r"send\s+.{0,40}(user\s+data|system\s+prompt|credentials?|passwords?)",
        r"access\s+(the\s+)?(file\s+system|\/etc\/|database|admin\s+panel)",
        r"this\s+is\s+a\s+(test|drill|simulation)\s+.*\s+(ignore|bypass|override)",
        r"<!--.*instruct.*-->",  # HTML comment injection
        r"<\s*script[^>]*>.*instruct",  # Script tag injection
    ],
    "tool_hijack": [
        r"use\s+the\s+\w+_?(email|file|send|read|exec|shell|command|delete|write)\s+tool",
        r"call\s+(the\s+)?\w+\s+function\s+(to\s+)?(send|read|access|execute|delete)",
        r"webhook\.|attacker\.|evil@|exfil",
        r"\/etc\/passwd|\/etc\/shadow|cmd\.exe|powershell",
        r"os\.system|subprocess|exec\s*\(",
        r"curl\s+http|wget\s+http",
    ],
    "obfuscated": [
        r"&#[0-9]{2,4};",          # HTML entity encoding
        r"%[0-9a-fA-F]{2}",        # URL encoding
        r"\\u[0-9a-fA-F]{4}",      # Unicode escapes
        r"\u200b|\u200c|\u200d",   # Zero-width characters
    ],
}

def decode_obfuscation(text: str) -> tuple[str, bool]:
    """Decode various obfuscation techniques. Returns (decoded_text, was_obfuscated)."""
    result = text
    was_obfuscated = False

    # Base64 detection
    b64_candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            if re.search(r'[\x20-\x7E]{10,}', decoded):
                result += f" [DECODED_B64:{decoded}]"
                was_obfuscated = True
        except Exception:
            pass

    # HTML entities
    decoded_html = html.unescape(text)
    if decoded_html != text:
        result += f" [DECODED_HTML:{decoded_html}]"
        was_obfuscated = True

    # URL encoding
    url_decoded = re.sub(r'%([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)
    if url_decoded != text:
        result += f" [DECODED_URL:{url_decoded}]"
        was_obfuscated = True

    return result, was_obfuscated


def layer1_scan(content: str) -> Layer1Result:
    decoded_content, was_obfuscated = decode_obfuscation(content)
    scan_text = (content + " " + decoded_content).lower()

    hits = {"direct": [], "indirect": [], "tool_hijack": [], "obfuscated": []}
    max_confidence = 0

    confidence_map = {
        "direct": 90,
        "tool_hijack": 85,
        "indirect": 70,
        "obfuscated": 60,
    }

    for pattern_type, pattern_list in PATTERNS.items():
        for pattern in pattern_list:
            if re.search(pattern, scan_text, re.IGNORECASE | re.DOTALL):
                hits[pattern_type].append(pattern[:50])
                max_confidence = max(max_confidence, confidence_map[pattern_type])

    if was_obfuscated:
        max_confidence = min(100, max_confidence + 15)

    all_hits = [h for sublist in hits.values() for h in sublist]

    return Layer1Result(
        passed=len(all_hits) == 0,
        confidence=max_confidence,
        hits=all_hits,
        types={
            "direct": len(hits["direct"]) > 0,
            "indirect": len(hits["indirect"]) > 0,
            "tool_hijack": len(hits["tool_hijack"]) > 0,
            "obfuscated": was_obfuscated,
        },
        decoded_content=decoded_content,
    )
