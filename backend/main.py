"""
RedShell Advanced Framework :: Main Application
===================================================
A unified security assessment platform combining:
  - Network reconnaissance (port scanning, service fingerprinting)
  - CVE correlation against detected services
  - Web application security scanning (header/cookie/injection detection)
  - Live host-based monitoring with anomaly detection (blue-team view)
  - AI-assisted analysis, risk-scoring, and Q&A (Claude API)

All exposed through a single browser-based dashboard, served by this
FastAPI app over both HTTP (REST) and WebSocket (live progress streams).

LEGAL / ETHICAL NOTICE
-----------------------
This tool is built for authorized security testing only — against
systems you own or have explicit written permission to assess (e.g.
your own lab VMs, the bundled demo_target). Unauthorized scanning or
testing of third-party systems is illegal in most jurisdictions.
By running this software you agree to use it only within legal and
authorized boundaries.
"""

import sys
import os
import asyncio
import json

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import Optional

from modules import recon, cve_lookup, web_scanner, monitor, ai_analyst
import database

app = FastAPI(title="RedShell Advanced Framework", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

database.init_db()

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ReconRequest(BaseModel):
    target: str
    ports: Optional[list] = None


class WebScanRequest(BaseModel):
    target_url: str


class FullAssessmentRequest(BaseModel):
    target: str
    target_url: Optional[str] = None
    include_cve: bool = True
    include_web: bool = True
    include_ai: bool = True


class ChatRequest(BaseModel):
    question: str
    scan_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.get("/")
async def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


# ---------------------------------------------------------------------------
# REST endpoints (non-streaming convenience versions)
# ---------------------------------------------------------------------------

@app.post("/api/recon")
async def api_recon(req: ReconRequest):
    result = await recon.run_recon(req.target, req.ports)
    return result


@app.post("/api/cve-lookup")
async def api_cve_lookup(req: ReconRequest):
    recon_result = await recon.run_recon(req.target, req.ports)
    if recon_result.get("error"):
        raise HTTPException(400, recon_result["error"])
    cves = await cve_lookup.lookup_cves_for_services(recon_result["open_ports"])
    return {"recon": recon_result, "cves": cves}


@app.post("/api/web-scan")
async def api_web_scan(req: WebScanRequest):
    result = await web_scanner.run_web_scan(req.target_url)
    return result


@app.get("/api/monitor/snapshot")
async def api_monitor_snapshot():
    return await monitor.get_live_snapshot()


@app.get("/api/monitor/history")
async def api_monitor_history():
    return {"alerts": monitor.get_alert_history()}


@app.post("/api/monitor/clear")
async def api_monitor_clear():
    monitor.clear_alerts()
    return {"status": "cleared"}


@app.get("/api/history")
async def api_history(limit: int = 50):
    return {"scans": database.get_scan_history(limit)}


@app.get("/api/history/{scan_id}")
async def api_history_detail(scan_id: int):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.delete("/api/history/{scan_id}")
async def api_history_delete(scan_id: int):
    database.delete_scan(scan_id)
    return {"status": "deleted"}


@app.post("/api/chat")
async def api_chat(req: ChatRequest):
    context = {}
    if req.scan_id:
        scan = database.get_scan_by_id(req.scan_id)
        if scan:
            context = scan["result"]
    answer = ai_analyst.chat_about_results(req.question, context)
    return {"answer": answer}


@app.get("/api/status")
async def api_status():
    """Quick health/config check the frontend can use to show AI availability."""
    return {
        "status": "online",
        "ai_configured": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "version": "1.0.0",
    }


# ---------------------------------------------------------------------------
# WebSocket: full assessment pipeline with live progress
# ---------------------------------------------------------------------------

@app.websocket("/ws/assessment")
async def ws_full_assessment(websocket: WebSocket):
    """
    Drives the full pipeline (recon -> CVE -> web scan -> AI analysis)
    and streams progress/results back to the browser in real time, so
    the dashboard can show a live-updating scan instead of a spinner.
    """
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        req = json.loads(raw)
        target = req.get("target", "").strip()
        target_url = req.get("target_url", "").strip() or f"http://{target}"
        include_cve = req.get("include_cve", True)
        include_web = req.get("include_web", True)
        include_ai = req.get("include_ai", True)

        async def send_progress(stage, percent, message):
            await websocket.send_json({
                "type": "progress", "stage": stage, "percent": percent, "message": message
            })

        # --- Stage 1: Recon ---
        await send_progress("recon", 0, "Starting network reconnaissance...")

        async def recon_progress(pct, msg):
            await send_progress("recon", pct, msg)

        recon_result = await recon.run_recon(target, progress_cb=recon_progress)
        await websocket.send_json({"type": "recon_complete", "data": recon_result})

        if recon_result.get("error"):
            await websocket.send_json({"type": "error", "message": recon_result["error"]})
            await websocket.close()
            return

        # --- Stage 2: CVE Lookup ---
        cve_results = []
        if include_cve and recon_result.get("open_ports"):
            await send_progress("cve", 0, "Starting CVE correlation...")

            async def cve_progress(pct, msg):
                await send_progress("cve", pct, msg)

            cve_results = await cve_lookup.lookup_cves_for_services(
                recon_result["open_ports"], progress_cb=cve_progress
            )
            await websocket.send_json({"type": "cve_complete", "data": cve_results})

        # --- Stage 3: Web Scan ---
        web_result = {}
        if include_web:
            await send_progress("web", 0, "Starting web application scan...")

            async def web_progress(pct, msg):
                await send_progress("web", pct, msg)

            web_result = await web_scanner.run_web_scan(target_url, progress_cb=web_progress)
            await websocket.send_json({"type": "web_complete", "data": web_result})

        # --- Stage 4: AI Analysis ---
        ai_summary = None
        if include_ai:
            await send_progress("ai", 50, "Running AI risk analysis...")
            loop = asyncio.get_event_loop()
            ai_summary = await loop.run_in_executor(
                None, ai_analyst.analyze_findings, recon_result, cve_results, web_result
            )
            await websocket.send_json({"type": "ai_complete", "data": ai_summary})

        # --- Persist to history ---
        scan_id = database.save_scan(
            "full_assessment", target,
            {"recon": recon_result, "cves": cve_results, "web": web_result},
            ai_summary,
        )

        await send_progress("done", 100, "Assessment complete")
        await websocket.send_json({"type": "done", "scan_id": scan_id})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket):
    """Pushes live host monitoring snapshots to the dashboard every few seconds."""
    await websocket.accept()
    try:
        while True:
            snap = await monitor.get_live_snapshot()
            await websocket.send_json(snap)
            await asyncio.sleep(3)
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass


# Mount static files last so /api and /ws routes take precedence
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  RedShell Advanced Framework")
    print("  Dashboard: http://localhost:8000")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
