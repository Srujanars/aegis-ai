#!/usr/bin/env python3
"""
AegisAI - Enterprise Shadow AI Data Leak Gateway & CISO Dashboard Server
Built with Python 3 Standard Library (http.server, json, urllib, datetime)
Zero external dependencies!
"""

import http.server
import socketserver
import json
import urllib.parse
from datetime import datetime
from pathlib import Path
import os
from engine import AegisGuard

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_FILE = BASE_DIR / "data" / "telemetry.json"
PORT = int(os.environ.get("PORT", 5050))


guard = AegisGuard()

# Pre-populate Telemetry History if not present
def init_telemetry():
    if not DATA_FILE.exists():
        initial_data = {
            "total_intercepted": 142,
            "threats_prevented": {
                "Cloud Credentials": 38,
                "Database Secrets": 44,
                "Financial / PII": 31,
                "API Tokens": 19,
                "Internal Infrastructure": 10
            },
            "recent_events": [
                {
                    "timestamp": "Today, 10:14 AM",
                    "user": "developer-arjun",
                    "entity_type": "AWS Access Key ID",
                    "category": "Cloud Credentials",
                    "severity": "CRITICAL",
                    "action": "Masked & Reversible",
                    "model_target": "OpenAI ChatGPT-4o"
                },
                {
                    "timestamp": "Today, 10:32 AM",
                    "user": "analyst-priya",
                    "entity_type": "Indian PAN Number",
                    "category": "Financial / PII",
                    "severity": "HIGH",
                    "action": "Masked & Reversible",
                    "model_target": "Claude 3.5 Sonnet"
                },
                {
                    "timestamp": "Today, 11:05 AM",
                    "user": "backend-dev-rohit",
                    "entity_type": "Database Connection URI with Password",
                    "category": "Database Secrets",
                    "severity": "CRITICAL",
                    "action": "Masked & Reversible",
                    "model_target": "DeepSeek R1"
                },
                {
                    "timestamp": "Today, 11:45 AM",
                    "user": "devops-neha",
                    "entity_type": "Internal Corporate Domain (.internal)",
                    "category": "Internal Infrastructure",
                    "severity": "MEDIUM",
                    "action": "Masked & Reversible",
                    "model_target": "GitHub Copilot"
                }
            ]
        }
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(initial_data, f, indent=2)

init_telemetry()

def load_telemetry():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_telemetry(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

class AegisHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def _send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/telemetry":
            self._send_json(load_telemetry())
            return
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        if parsed.path == "/api/intercept":
            raw_prompt = req_data.get("prompt", "")
            user_name = req_data.get("user", "developer-shiv")
            model_target = req_data.get("model", "OpenAI ChatGPT-4o")

            # 1. Sanitize & Tokenize
            sanitized_res = guard.sanitize(raw_prompt)
            session_id = sanitized_res["session_id"]
            sanitized_prompt = sanitized_res["sanitized_prompt"]
            threats = sanitized_res["threats_detected"]

            # 2. Simulate AI Processing on the sanitized prompt (what public AI sees)
            ai_raw_response = guard.simulate_ai_response(sanitized_prompt)

            # 3. Reverse De-tokenization (local re-hydration)
            rehydrated_solution = guard.detokenize(ai_raw_response, session_id)

            # 4. Update Audit Telemetry (Metadata only, NEVER logs actual secrets)
            telemetry = load_telemetry()
            if threats:
                telemetry["total_intercepted"] += len(threats)
                for t in threats:
                    cat = t.get("category", "General Secrets")
                    telemetry["threats_prevented"][cat] = telemetry["threats_prevented"].get(cat, 0) + 1
                    
                    event = {
                        "timestamp": datetime.now().strftime("%I:%M %p"),
                        "user": user_name,
                        "entity_type": t.get("type", "Secret"),
                        "category": cat,
                        "severity": t.get("severity", "HIGH"),
                        "action": "Masked & Reversible",
                        "model_target": model_target
                    }
                    telemetry["recent_events"].insert(0, event)

                # Keep last 50 events
                telemetry["recent_events"] = telemetry["recent_events"][:50]
                save_telemetry(telemetry)

            self._send_json({
                "session_id": session_id,
                "raw_prompt": raw_prompt,
                "sanitized_prompt": sanitized_prompt,
                "ai_received_prompt": sanitized_prompt,
                "ai_raw_response": ai_raw_response,
                "rehydrated_solution": rehydrated_solution,
                "threats_detected": threats,
                "latency_ms": 1.2,
                "compliance_status": "SECURE",
                "dpdp_compliant": True,
                "gdpr_compliant": True
            })
            return

        self._send_json({"error": "Endpoint not found"}, 404)

def run():
    with socketserver.TCPServer(("", PORT), AegisHandler) as httpd:
        print(f"🛡️  AegisAI Server active at http://localhost:{PORT}")
        print("Ready for live dual-screen developer & CISO demo!")
        httpd.serve_forever()

if __name__ == "__main__":
    run()
