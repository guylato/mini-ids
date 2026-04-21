from collections import defaultdict, deque

from scapy import packet
from app.database import get_connection
from app.models import PacketEvent, AlertEvent
from app.utils import severity_from_score


class IDSDetector:
    def __init__(self):
        self.port_scan = defaultdict(lambda: deque(maxlen=100))
        self.packet_rate = defaultdict(lambda: deque(maxlen=200))

    def store_packet(self, packet: PacketEvent):
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol,
            src_port, dst_port, length, tcp_flags, payload_preview, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet.timestamp,
                packet.src_ip,
                packet.dst_ip,
                packet.protocol,
                packet.src_port,
                packet.dst_port,
                packet.length,
                packet.tcp_flags,
                packet.payload_preview,
                packet.user_agent,
            ),
        )

        conn.commit()
        conn.close()

    def store_alert(self, alert: AlertEvent):
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO alerts (timestamp, src_ip, dst_ip, protocol,
            alert_type, severity, score, description, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.timestamp,
                alert.src_ip,
                alert.dst_ip,
                alert.protocol,
                alert.alert_type,
                alert.severity,
                alert.score,
                alert.description,
                alert.status,
            ),
        )

        conn.commit()
        conn.close()

    def analyze_packet(self, packet: PacketEvent):
        alerts = []

        self.store_packet(packet)

        alerts += self.detect_port_scan(packet)
        alerts += self.detect_flood(packet)

        for alert in alerts:
            self.store_alert(alert)

        return alerts

    def detect_port_scan(self, packet: PacketEvent):
        if packet.protocol != "TCP" or packet.dst_port is None:
         return []

        self.port_scan[packet.src_ip].append(packet.dst_port)
        unique_ports = set(self.port_scan[packet.src_ip])

        if len(unique_ports) >= 10:
        # éviter spam
            if hasattr(self, "already_alerted") and packet.src_ip in self.already_alerted:
                return []

            if not hasattr(self, "already_alerted"):
                self.already_alerted = set()

            self.already_alerted.add(packet.src_ip)

            score = min(10, len(unique_ports) / 2)

            return [
                AlertEvent(
                    timestamp=packet.timestamp,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    protocol=packet.protocol,
                    alert_type="network_scan",
                    severity=severity_from_score(score),
                    score=score,
                    description=f"Scan de ports détecté ({len(unique_ports)} ports ciblés)",
                )
            ]

        return []

    def detect_flood(self, packet: PacketEvent):
        self.packet_rate[packet.src_ip].append(packet.timestamp)
        count = len(self.packet_rate[packet.src_ip])

        if count > 50:
            score = min(10, count / 10)
            return [
                AlertEvent(
                    timestamp=packet.timestamp,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    protocol=packet.protocol,
                    alert_type="flood",
                    severity=severity_from_score(score),
                    score=score,
                    description=f"Trop de paquets envoyés ({count})",
                )
            ]

        return []

    def get_stats(self):
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM packets")
        total_packets = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cur.fetchone()[0]

        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
        alerts = cur.fetchall()

        conn.close()

        return {
            "total_packets": total_packets,
            "total_alerts": total_alerts,
            "alerts": alerts,
        }


detector = IDSDetector()