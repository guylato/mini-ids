from app.detector import detector
from app.models import PacketEvent
from app.utils import now_iso


class TrafficSimulator:

    @staticmethod
    def send_packet(src_ip, dst_ip, protocol, src_port, dst_port, length=60, payload="", user_agent=""):
        packet = PacketEvent(
            timestamp=now_iso(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            tcp_flags="S",
            payload_preview=payload,
            user_agent=user_agent,
        )
        detector.analyze_packet(packet)

    @staticmethod
    def simulate_port_scan(src_ip, dst_ip, count=20):
        for i in range(count):
            TrafficSimulator.send_packet(
                src_ip,
                dst_ip,
                "TCP",
                40000 + i,
                20 + i
            )
        return {"message": f"Scan simulé ({count} paquets)"}

    @staticmethod
    def simulate_flood(src_ip, dst_ip, count=100):
        for i in range(count):
            TrafficSimulator.send_packet(
                src_ip,
                dst_ip,
                "UDP",
                50000 + (i % 10),
                80
            )
        return {"message": f"Flood simulé ({count} paquets)"}

    @staticmethod
    def simulate_http_attack(src_ip, dst_ip):
        TrafficSimulator.send_packet(
            src_ip,
            dst_ip,
            "TCP",
            50505,
            80,
            payload="GET /../../etc/passwd HTTP/1.1 User-Agent: sqlmap",
            user_agent="sqlmap"
        )
        return {"message": "Attaque HTTP simulée"}