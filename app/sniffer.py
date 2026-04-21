from typing import Optional
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, Raw

from app.detector import detector
from app.models import PacketEvent
from app.utils import now_iso, preview_bytes

sniffer_instance: Optional[AsyncSniffer] = None

SNIFFER_STATUS = {
    "running": False,
    "iface": None,
    "mode": "idle",
}


def extract_user_agent(payload_preview: str) -> str:
    if "User-Agent:" in payload_preview:
        try:
            return payload_preview.split("User-Agent:")[1].split("  ")[0].strip()
        except IndexError:
            return ""
    return ""


def process_packet(pkt) -> None:
    if IP not in pkt:
        return

    ip_layer = pkt[IP]
    protocol = "OTHER"
    src_port = None
    dst_port = None
    tcp_flags = ""
    payload_preview = ""
    user_agent = ""

    if TCP in pkt:
        protocol = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        tcp_flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        protocol = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "ICMP"

    if Raw in pkt:
        payload_preview = preview_bytes(bytes(pkt[Raw]))
        user_agent = extract_user_agent(payload_preview)

    event = PacketEvent(
        timestamp=now_iso(),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=len(pkt),
        tcp_flags=tcp_flags,
        payload_preview=payload_preview,
        user_agent=user_agent,
    )

    detector.analyze_packet(event)


def start_sniffer(iface: Optional[str] = None, packet_filter: str = "ip") -> dict:
    global sniffer_instance

    if sniffer_instance and SNIFFER_STATUS["running"]:
        return {"message": "Le sniffer tourne déjà."}

    sniffer_instance = AsyncSniffer(
        iface=iface,
        filter=packet_filter,
        prn=process_packet,
        store=False,
    )
    sniffer_instance.start()

    SNIFFER_STATUS["running"] = True
    SNIFFER_STATUS["iface"] = iface
    SNIFFER_STATUS["mode"] = "live"

    return {"message": "Capture démarrée.", "iface": iface, "filter": packet_filter}


def stop_sniffer() -> dict:
    global sniffer_instance

    if not sniffer_instance or not SNIFFER_STATUS["running"]:
        return {"message": "Aucune capture en cours."}

    sniffer_instance.stop()
    sniffer_instance = None
    SNIFFER_STATUS["running"] = False
    SNIFFER_STATUS["iface"] = None
    SNIFFER_STATUS["mode"] = "idle"

    return {"message": "Capture arrêtée."}


def get_sniffer_status() -> dict:
    return SNIFFER_STATUS