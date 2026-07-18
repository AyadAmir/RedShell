#!/bin/bash
# ============================================================
#  RedShell Advanced Framework - Linux / macOS Launcher
# ============================================================
set -e

echo "============================================================"
echo "  RedShell Advanced Framework - Starting Up"
echo "============================================================"
echo ""

# --- Check Python ---
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 was not found. Please install Python 3.10+."
    exit 1
fi

# --- Create virtual environment if missing ---
if [ ! -d "venv" ]; then
    echo "[SETUP] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "[SETUP] Installing/checking dependencies..."
pip install -q --disable-pip-version-check -r backend/requirements.txt
pip install -q --disable-pip-version-check flask

# --- Load .env if present ---
if [ -f ".env" ]; then
    echo "[SETUP] Loading environment variables from .env..."
    export $(grep -v '^#' .env | xargs)
else
    echo ""
    echo "[INFO] No .env file found. AI Analyst will run in rule-based fallback mode."
    echo "[INFO] To enable full AI analysis, create a .env file with:"
    echo "       ANTHROPIC_API_KEY=your_key_here"
    echo ""
fi

# --- Start demo target in background ---
echo "[START] Launching demo target on http://localhost:5050 ..."
python3 demo_target/vulnerable_app.py > /tmp/redshell_demo.log 2>&1 &
DEMO_PID=$!

sleep 2

echo "[START] Launching RedShell dashboard on http://localhost:8000 ..."
echo ""
echo "============================================================"
echo "  Dashboard:    http://localhost:8000"
echo "  Demo target:  http://localhost:5050"
echo "  Press CTRL+C to stop RedShell."
echo "============================================================"
echo ""

# Try to open browser (works on most Linux desktops and macOS)
( sleep 1 && (xdg-open http://localhost:8000 2>/dev/null || open http://localhost:8000 2>/dev/null || true) ) &

# --- Cleanup demo target on exit ---
trap "echo ''; echo '[STOP] Shutting down demo target...'; kill $DEMO_PID 2>/dev/null" EXIT

cd backend
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
