from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def severity_from_score(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def preview_bytes(raw: bytes, limit: int = 120) -> str:
    if not raw:
        return ""
    cleaned = raw[:limit].decode(errors="ignore").replace("\n", " ").replace("\r", " ")
    return cleaned.strip()