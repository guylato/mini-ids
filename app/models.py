from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketEvent:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    tcp_flags: str = ""
    payload_preview: str = ""
    user_agent: str = ""


@dataclass
class AlertEvent:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    alert_type: str
    severity: str
    score: float
    description: str
    status: str = "new"