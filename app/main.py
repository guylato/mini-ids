from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.database import init_db
from app.detector import detector
from app.schemas import PacketIn, SimulateRequest
from app.sniffer import start_sniffer, stop_sniffer, get_sniffer_status
from app.simulator import TrafficSimulator
from app.utils import now_iso

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    stats = detector.get_stats()
    status = get_sniffer_status()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "stats": stats,
            "status": status,
        },
    )


@app.get("/health")
def health():
    return {"status": "ok", "time": now_iso()}


@app.post("/simulate")
def simulate(req: SimulateRequest):
    if req.kind == "port_scan":
        return TrafficSimulator.simulate_port_scan(req.src_ip, req.dst_ip, req.count)
    elif req.kind == "flood":
        return TrafficSimulator.simulate_flood(req.src_ip, req.dst_ip, req.count)
    elif req.kind == "http":
        return TrafficSimulator.simulate_http_attack(req.src_ip, req.dst_ip)

    return {"error": "type inconnu"}


@app.post("/sniffer/start")
def start():
    return start_sniffer()


@app.post("/sniffer/stop")
def stop():
    return stop_sniffer()


@app.get("/report.txt", response_class=PlainTextResponse)
def report():
    stats = detector.get_stats()

    lines = []
    lines.append("=== RAPPORT IDS ===")
    lines.append(f"Total paquets : {stats['total_packets']}")
    lines.append(f"Total alertes : {stats['total_alerts']}")
    lines.append("")

    for alert in stats["alerts"]:
        lines.append(f"{alert['timestamp']} | {alert['alert_type']} | {alert['description']}")

    return "\n".join(lines)