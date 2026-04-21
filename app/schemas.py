from pydantic import BaseModel
from typing import Optional


class PacketIn(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    tcp_flags: str = ""
    payload_preview: str = ""
    user_agent: str = ""


class SimulateRequest(BaseModel):
    kind: str = "port_scan"
    src_ip: str = "192.168.1.50"
    dst_ip: str = "192.168.1.10"
    count: int = 20