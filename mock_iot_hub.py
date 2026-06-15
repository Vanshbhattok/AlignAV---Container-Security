#!/usr/bin/env python3
import json
import re
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import threading

PORT = 8080
HOST = "0.0.0.0"

# Global state tracking
lock = threading.Lock()
devices = {}            # device_id -> {status, last_seen, tpm_status, tpm_ek}
acr_registry = {
    "temp-sensor-module:v1.0.0-signed": {
        "signed": True,
        "signature_key": "SHA256:alignav-signing-vault-key-pub",
        "vuln_critical": 0,
        "vuln_high": 0,
        "vuln_medium": 2,
        "vuln_low": 5,
        "status": "Secure"
    },
    "custom-analytics:latest": {
        "signed": False,
        "signature_key": "None",
        "vuln_critical": 1,
        "vuln_high": 3,
        "vuln_medium": 6,
        "vuln_low": 12,
        "status": "Insecure"
    }
}
deployment_rules = {}   # Holds findings from parsing deployment.json
security_alerts = []    # List of runtime alarms from Defender for IoT
sse_clients = []
telemetry_log = []

def parse_deployment_manifest():
    global deployment_rules
    try:
        with open("deployment.json", "r") as f:
            manifest = json.load(f)
        
        modules = manifest.get("modulesContent", {}).get("$edgeAgent", {}).get("properties.desired.modules", {})
        findings = []
        for name, config in modules.items():
            image = config.get("settings", {}).get("image", "")
            create_options = config.get("settings", {}).get("createOptions", {})
            host_config = create_options.get("HostConfig", {})
            
            privileged = host_config.get("Privileged", False)
            readonly = host_config.get("ReadonlyRootfs", False)
            user = host_config.get("User", "root")
            
            # Check rules
            image_meta = acr_registry.get(image.split("/")[-1], {"signed": False, "status": "Untrusted"})
            
            module_finding = {
                "name": name,
                "image": image,
                "signed": image_meta.get("signed", False),
                "privileged": privileged,
                "readonly": readonly,
                "user": user,
                "violations": []
            }
            
            if privileged:
                module_finding["violations"].append({
                    "severity": "HIGH",
                    "rule": "Container should not run in privileged mode (--privileged)",
                    "resolution": "Set HostConfig.Privileged to false to isolate device namespaces."
                })
            if not readonly:
                module_finding["violations"].append({
                    "severity": "MEDIUM",
                    "rule": "Container filesystem should be mounted as read-only",
                    "resolution": "Set HostConfig.ReadonlyRootfs to true to prevent directory payload modifications."
                })
            if user == "root":
                module_finding["violations"].append({
                    "severity": "HIGH",
                    "rule": "Container should run as non-root user context",
                    "resolution": "Set HostConfig.User to a non-zero UID (e.g. 1000:1000)."
                })
            if not image_meta.get("signed", False):
                module_finding["violations"].append({
                    "severity": "CRITICAL",
                    "rule": "Container image signature verification failed",
                    "resolution": "Sign built images using Cosign and publish verification public keys."
                })
                
            findings.append(module_finding)
            
        with lock:
            deployment_rules["modules"] = findings
            deployment_rules["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        print(f"Error parsing deployment.json: {e}")
        with lock:
            deployment_rules = {"error": str(e)}

def add_security_alert(alert):
    with lock:
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert["timestamp"] = timestamp
        if alert.get("action") == "RESTORE":
            global security_alerts
            security_alerts = [alert]
        else:
            security_alerts.append(alert)
            if len(security_alerts) > 30:
                security_alerts.pop(0)
    print(f"\033[91m[Defender Alert]\033[0m {alert['message']} (Severity: {alert['severity']})")
    notify_clients()

def notify_clients():
    with lock:
        payload = json.dumps({
            "devices": devices,
            "registry": acr_registry,
            "deployment": deployment_rules,
            "alerts": security_alerts,
            "telemetry": telemetry_log[-15:]
        })
    
    dead_clients = []
    for q in sse_clients:
        try:
            q.put(payload)
        except Exception:
            dead_clients.append(q)
            
    for q in dead_clients:
        if q in sse_clients:
            sse_clients.remove(q)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

class MockIoTHubHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_POST(self):
        if self.path == "/devices/register":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            
            device_id = data.get("device_id")
            tpm_status = data.get("tpm_status")
            tpm_ek = data.get("tpm_ek")
            
            with lock:
                devices[device_id] = {
                    "status": "Online",
                    "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "tpm_status": tpm_status,
                    "tpm_ek": tpm_ek,
                    "modules": ["edgeAgent", "edgeHub"]
                }
            
            print(f"\033[92m[IoT Hub]\033[0m Device registered via TPM attestation: \033[93m{device_id}\033[0m")
            notify_clients()
            self._send_json(200, {"status": "registered", "assigned_hub": "alignav-hub-dps.azure-devices.net"})
            
        elif self.path == "/devices/telemetry":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            
            device_id = data.get("device_id")
            payload = data.get("payload", {})
            
            with lock:
                if device_id in devices:
                    devices[device_id]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                telemetry_log.append({
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "device_id": device_id,
                    "data": payload
                })
                if len(telemetry_log) > 50:
                    telemetry_log.pop(0)
            
            notify_clients()
            self._send_json(204, {})
            
        elif self.path == "/devices/security-alerts":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            
            add_security_alert(data)
            self._send_json(200, {"status": "alert_logged"})
            
        elif self.path == "/devices/update-modules":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            
            device_id = data.get("device_id")
            modules_list = data.get("modules", [])
            
            with lock:
                if device_id in devices:
                    devices[device_id]["modules"] = modules_list
            notify_clients()
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
            
        elif self.path == "/devices/deployment":
            try:
                with open("deployment.json", "r") as f:
                    manifest = json.load(f)
                self._send_json(200, manifest)
            except Exception as e:
                self._send_json(500, {"error": str(e)})
                
        elif self.path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            import queue
            q = queue.Queue()
            sse_clients.append(q)
            
            # Send initial state
            with lock:
                initial_payload = json.dumps({
                    "devices": devices,
                    "registry": acr_registry,
                    "deployment": deployment_rules,
                    "alerts": security_alerts,
                    "telemetry": telemetry_log[-15:]
                })
            try:
                self.wfile.write(f"data: {initial_payload}\n\n".encode("utf-8"))
                self.wfile.flush()
            except Exception:
                if q in sse_clients:
                    sse_clients.remove(q)
                return

            while True:
                try:
                    data = q.get(timeout=10)
                    self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except Exception:
                        break
                except Exception:
                    break
            
            if q in sse_clients:
                sse_clients.remove(q)
        else:
            self._send_json(404, {"error": "Not Found"})

# HTML Dashboard template
HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AlignAV | Local Container Security Hub</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Fira+Code:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #080c14;
            --bg-card: rgba(15, 23, 42, 0.6);
            --border-color: rgba(255, 255, 255, 0.08);
            
            --text-main: #f8fafc;
            --text-sec: #94a3b8;
            
            --color-teal: #00f2fe;
            --color-indigo: #6366f1;
            --color-red: #ef4444;
            --color-amber: #f59e0b;
            --color-green: #10b981;
            --color-blue: #3b82f6;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(0, 242, 254, 0.05) 0%, transparent 40%);
            background-attachment: fixed;
        }

        header {
            padding: 20px 40px;
            border-bottom: 1px solid var(--border-color);
            background: rgba(8, 12, 20, 0.8);
            backdrop-filter: blur(12px);
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--color-teal), var(--color-indigo));
            border-radius: 8px;
            display: grid;
            place-items: center;
            font-weight: 800;
            color: var(--bg-dark);
            font-size: 20px;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.3);
        }

        .logo-text {
            font-size: 20px;
            font-weight: 800;
            letter-spacing: 0.05em;
        }

        .logo-text span {
            color: var(--color-teal);
        }

        .system-badge {
            background: rgba(0, 242, 254, 0.1);
            border: 1px solid rgba(0, 242, 254, 0.2);
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            color: var(--color-teal);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .badge-dot {
            width: 8px;
            height: 8px;
            background: var(--color-teal);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--color-teal);
            animation: pulse-dot 2s infinite;
        }

        @keyframes pulse-dot {
            0% { transform: scale(0.95); opacity: 0.5; }
            50% { transform: scale(1.1); opacity: 1; box-shadow: 0 0 12px var(--color-teal); }
            100% { transform: scale(0.95); opacity: 0.5; }
        }

        main {
            flex: 1;
            padding: 30px 40px;
            display: grid;
            grid-template-columns: 1fr 1.3fr;
            gap: 30px;
            max-width: 1600px;
            margin: 0 auto;
            width: 100%;
        }

        .panel-column {
            display: flex;
            flex-direction: column;
            gap: 30px;
        }

        .glass-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            backdrop-filter: blur(16px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            transition: border-color 0.3s ease;
        }

        .glass-card:hover {
            border-color: rgba(99, 102, 241, 0.2);
        }

        .glass-card h2 {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 20px;
            border-left: 3px solid var(--color-teal);
            padding-left: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .panel-subtitle {
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.05em;
            color: var(--text-sec);
            background: rgba(255, 255, 255, 0.04);
            padding: 3px 8px;
            border-radius: 4px;
        }

        /* Device Info List */
        .device-row {
            background: rgba(255, 255, 255, 0.01);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .device-main-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .device-id {
            font-weight: 600;
            font-size: 16px;
        }

        .device-state {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--color-green);
        }

        .device-tpm {
            display: grid;
            grid-template-columns: 1.2fr 2fr;
            border-top: 1px dashed var(--border-color);
            padding-top: 10px;
            font-size: 13px;
            gap: 8px;
        }

        .tpm-key {
            font-family: 'Fira Code', monospace;
            font-size: 11px;
            color: var(--color-teal);
            background: rgba(0, 242, 254, 0.05);
            padding: 1px 6px;
            border-radius: 4px;
            text-overflow: ellipsis;
            overflow: hidden;
            white-space: nowrap;
        }

        .modules-running-wrapper {
            margin-top: 10px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .modules-title {
            font-size: 12px;
            color: var(--text-sec);
            font-weight: 600;
        }

        .module-pills {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .module-pill {
            font-size: 12px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 4px 10px;
            border-radius: 6px;
            font-family: 'Fira Code', monospace;
            transition: var(--transition-quick);
        }

        .module-pill.system {
            border-color: rgba(99, 102, 241, 0.3);
            color: #a5b4fc;
        }

        .module-pill.active-secure {
            border-color: rgba(16, 185, 129, 0.3);
            color: #a7f3d0;
            background: rgba(16, 185, 129, 0.05);
        }

        .module-pill.suspended {
            border-color: rgba(239, 68, 68, 0.4);
            color: #fca5a5;
            background: rgba(239, 68, 68, 0.1);
            animation: alert-blink 1s infinite alternate;
        }

        /* Container Registry ACR list */
        .acr-grid {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .acr-item {
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 16px;
            background: rgba(255, 255, 255, 0.01);
        }

        .acr-header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .acr-image-name {
            font-family: 'Fira Code', monospace;
            font-size: 14px;
            font-weight: 600;
        }

        .acr-badge {
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            text-transform: uppercase;
        }

        .acr-badge.secure {
            background: rgba(16, 185, 129, 0.15);
            color: var(--color-green);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .acr-badge.insecure {
            background: rgba(245, 158, 11, 0.15);
            color: var(--color-amber);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }

        .acr-meta {
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            font-size: 12px;
            color: var(--text-sec);
            gap: 8px;
        }

        .acr-sig-status {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .sig-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }

        .acr-cves {
            display: flex;
            gap: 8px;
        }

        .cve-pill {
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 700;
        }

        .cve-pill.crit {
            background: rgba(239, 68, 68, 0.2);
            color: var(--color-red);
        }

        .cve-pill.high {
            background: rgba(245, 158, 11, 0.2);
            color: var(--color-amber);
        }

        /* Deployment scan findings */
        .scan-findings-container {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .scan-module-finding {
            border: 1px solid var(--border-color);
            background: rgba(255, 255, 255, 0.01);
            border-radius: 12px;
            padding: 16px;
        }

        .scan-module-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px dashed var(--border-color);
            padding-bottom: 8px;
            margin-bottom: 10px;
        }

        .scan-module-name {
            font-weight: 700;
            font-size: 14px;
        }

        .violations-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .violation-item {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 10px;
            font-size: 12.5px;
            align-items: flex-start;
        }

        .violation-badge {
            font-size: 10px;
            padding: 1px 5px;
            border-radius: 3px;
            font-weight: 800;
            text-align: center;
            text-transform: uppercase;
        }

        .violation-badge.CRITICAL {
            background: var(--color-red);
            color: white;
        }

        .violation-badge.HIGH {
            background: var(--color-amber);
            color: black;
        }

        .violation-badge.MEDIUM {
            background: #eab308;
            color: black;
        }

        .violation-text {
            color: var(--text-main);
        }

        .violation-resolution {
            font-size: 11.5px;
            color: var(--text-sec);
            margin-top: 2px;
            font-style: italic;
        }

        /* Defender Logs Terminal */
        .defender-log-box {
            font-family: 'Fira Code', monospace;
            background: #030712;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            height: 250px;
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 8px;
            font-size: 11.5px;
            box-shadow: inset 0 4px 15px rgba(0,0,0,0.8);
        }

        .console-line {
            line-height: 1.4;
            color: var(--text-sec);
        }

        .console-line.info {
            color: var(--color-blue);
        }

        .console-line.alert-high {
            color: var(--color-red);
            font-weight: bold;
            animation: alert-blink 1s infinite alternate;
        }

        .console-line.alert-med {
            color: var(--color-amber);
        }

        .console-line.success {
            color: var(--color-green);
        }

        @keyframes alert-blink {
            from { text-shadow: 0 0 2px rgba(239,68,68,0.2); }
            to { text-shadow: 0 0 8px rgba(239,68,68,0.7); }
        }

        .empty-state {
            color: var(--text-sec);
            font-size: 13px;
            text-align: center;
            padding: 30px 10px;
            border: 1px dashed var(--border-color);
            border-radius: 10px;
        }
        
        /* Telemetry streams */
        .telemetry-row {
            font-size: 12px;
            padding: 8px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.02);
            display: grid;
            grid-template-columns: 80px 1.5fr 2fr;
            gap: 10px;
        }

        .tel-time {
            color: var(--text-sec);
            font-family: 'Fira Code', monospace;
        }

        .tel-device {
            font-weight: 600;
            color: var(--color-indigo);
        }

        .tel-payload {
            font-family: 'Fira Code', monospace;
            color: var(--color-teal);
        }

        @media (max-width: 1024px) {
            main {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-container">
            <div class="logo-icon">A</div>
            <div class="logo-text">Align<span>AV</span></div>
        </div>
        <div class="system-badge">
            <span class="badge-dot"></span>
            <span>Container Security Simulation</span>
        </div>
    </header>

    <main>
        <div class="panel-column">
            <!-- Active Node -->
            <div class="glass-card">
                <h2>IoT Edge Nodes <span class="panel-subtitle">TPM 2.0 Attested</span></h2>
                <div id="devices-container">
                    <div class="empty-state">No Edge devices registered. Bootstrap mock_edge_device.py.</div>
                </div>
            </div>

            <!-- ACR registry -->
            <div class="glass-card">
                <h2>Container Registry (ACR) <span class="panel-subtitle">Defender & Cosign</span></h2>
                <div class="acr-grid" id="acr-container">
                    <!-- Injected by SSE -->
                </div>
            </div>
        </div>

        <div class="panel-column">
            <!-- Deployment Manifest check -->
            <div class="glass-card">
                <h2>Manifest Policy Evaluation <span class="panel-subtitle">Hub Gates</span></h2>
                <div class="scan-findings-container" id="findings-container">
                    <!-- Injected by SSE -->
                </div>
            </div>

            <!-- Defender for IoT alert terminal -->
            <div class="glass-card">
                <h2>Defender for IoT Alerts <span class="panel-subtitle">Runtime Log</span></h2>
                <div class="defender-log-box" id="defender-console">
                    <div class="console-line info">[SYSTEM] Security Agent standing by. Ingesting alerts at port 8080...</div>
                </div>
            </div>
            
            <!-- Telemetry list -->
            <div class="glass-card" style="padding: 16px;">
                <h3 style="font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-sec); margin-bottom: 10px;">Environmental Ingestion Stream</h3>
                <div id="telemetry-container" style="max-height: 120px; overflow-y: auto;">
                    <div class="empty-state" style="padding: 10px;">Waiting for telemetry...</div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const devicesContainer = document.getElementById('devices-container');
        const acrContainer = document.getElementById('acr-container');
        const findingsContainer = document.getElementById('findings-container');
        const defenderConsole = document.getElementById('defender-console');
        const telemetryContainer = document.getElementById('telemetry-container');

        // Setup Server-Sent Events
        const es = new EventSource('/api/stream');

        es.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            // 1. Devices update
            const deviceEntries = Object.entries(data.devices);
            if (deviceEntries.length === 0) {
                devicesContainer.innerHTML = '<div class="empty-state">No Edge devices registered. Bootstrap mock_edge_device.py.</div>';
            } else {
                let html = '';
                deviceEntries.forEach(([id, dev]) => {
                    const statusText = dev.status;
                    const modulesHtml = dev.modules.map(modName => {
                        let classState = 'system';
                        // Check if this module is suspended under security incident
                        const isSuspended = data.alerts.some(alert => 
                            alert.module === modName && alert.action === 'ISOLATE'
                        );
                        
                        if (isSuspended) {
                            classState = 'suspended';
                        } else if (modName !== 'edgeAgent' && modName !== 'edgeHub') {
                            classState = 'active-secure';
                        }
                        return `<span class="module-pill ${classState}">${modName}</span>`;
                    }).join('');

                    html += `
                    <div class="device-row">
                        <div class="device-main-info">
                            <span class="device-id">${id}</span>
                            <span class="device-state">${statusText}</span>
                        </div>
                        <div class="device-tpm">
                            <span>TPM Root of Trust:</span>
                            <span style="color: ${dev.tpm_status === 'Attested' ? 'var(--color-green)' : 'var(--color-red)'}; font-weight:700;">
                                ${dev.tpm_status}
                            </span>
                            <span>Endorsement Key:</span>
                            <span class="tpm-key" title="${dev.tpm_ek}">${dev.tpm_ek}</span>
                        </div>
                        <div class="modules-running-wrapper">
                            <div class="modules-title">Active Edge Containers:</div>
                            <div class="module-pills">${modulesHtml}</div>
                        </div>
                    </div>`;
                });
                devicesContainer.innerHTML = html;
            }

            // 2. Container Registry (ACR)
            let acrHtml = '';
            Object.entries(data.registry).forEach(([imgName, meta]) => {
                const badgeClass = meta.status === 'Secure' ? 'secure' : 'insecure';
                acrHtml += `
                <div class="acr-item">
                    <div class="acr-header-row">
                        <span class="acr-image-name">${imgName}</span>
                        <span class="acr-badge ${badgeClass}">${meta.status}</span>
                    </div>
                    <div class="acr-meta">
                        <div class="acr-sig-status">
                            <span class="sig-dot" style="background: ${meta.signed ? 'var(--color-green)' : 'var(--color-red)'}"></span>
                            <span>Cosign Signature: ${meta.signed ? 'Verified' : 'Unsigned'}</span>
                        </div>
                        <div class="acr-cves">
                            <span class="cve-pill crit">${meta.vuln_critical} Critical</span>
                            <span class="cve-pill high">${meta.vuln_high} High</span>
                        </div>
                    </div>
                </div>`;
            });
            acrContainer.innerHTML = acrHtml;

            // 3. Deployment Manifest Findings
            if (!data.deployment.modules) {
                findingsContainer.innerHTML = '<div class="empty-state">No deployment manifest parsed. Re-verify config.</div>';
            } else {
                let rulesHtml = '';
                data.deployment.modules.forEach(mod => {
                    const hasViolations = mod.violations.length > 0;
                    const blockText = hasViolations ? '<span style="color:var(--color-red); font-weight:700;">DEPLOYMENT BLOCKED</span>' : '<span style="color:var(--color-green); font-weight:700;">AUTHORIZED</span>';
                    
                    let violationsHtml = '';
                    if (!hasViolations) {
                        violationsHtml = '<div style="color:var(--color-green); font-size:12px;">✓ Verified least privilege options.</div>';
                    } else {
                        violationsHtml = mod.violations.map(v => `
                        <div class="violation-item">
                            <span class="violation-badge ${v.severity}">${v.severity}</span>
                            <div>
                                <span class="violation-text">${v.rule}</span>
                                <div class="violation-resolution">Fix: ${v.resolution}</div>
                            </div>
                        </div>`).join('');
                    }

                    rulesHtml += `
                    <div class="scan-module-finding">
                        <div class="scan-module-header">
                            <span class="scan-module-name">${mod.name}</span>
                            <span class="acr-image-name" style="font-size:11px;">${mod.image.split('/')[-1] || mod.image}</span>
                        </div>
                        <div style="font-size:12px; margin-bottom:10px; color:var(--text-sec);">
                            Status: ${blockText}
                        </div>
                        <div class="violations-list">
                            ${violationsHtml}
                        </div>
                    </div>`;
                });
                findingsContainer.innerHTML = rulesHtml;
            }

            // 4. Defender Logs
            if (data.alerts.length === 0) {
                defenderConsole.innerHTML = '<div class="console-line info">[SYSTEM] Security Agent standing by. Ingesting alerts at port 8080...</div>';
            } else {
                defenderConsole.innerHTML = '';
                data.alerts.forEach(alert => {
                    const line = document.createElement('div');
                    line.className = `console-line ${alert.severity === 'HIGH' ? 'alert-high' : 'alert-med'}`;
                    line.textContent = `[${alert.timestamp}] [DEFENDER] [${alert.severity}] Device: ${alert.device_id} | Module: ${alert.module} | Message: ${alert.message} -> Action: ${alert.action}`;
                    defenderConsole.appendChild(line);
                });
                defenderConsole.scrollTop = defenderConsole.scrollHeight;
            }

            // 5. Ingestion stream
            if (data.telemetry.length === 0) {
                telemetryContainer.innerHTML = '<div class="empty-state" style="padding:10px;">Waiting for telemetry...</div>';
            } else {
                let telHtml = '';
                data.telemetry.slice().reverse().forEach(tel => {
                    telHtml += `
                    <div class="telemetry-row">
                        <span class="tel-time">${tel.timestamp}</span>
                        <span class="tel-device">${tel.device_id}</span>
                        <span class="tel-payload">${JSON.stringify(tel.data)}</span>
                    </div>`;
                });
                telemetryContainer.innerHTML = telHtml;
            }
        };

        es.onerror = function() {
            console.error("SSE stream connection lost.");
        };
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    parse_deployment_manifest()
    server = ThreadedHTTPServer((HOST, PORT), MockIoTHubHandler)
    print(f"\033[92m[Mock IoT Hub]\033[0m Server successfully running at http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Mock IoT Hub] Exiting...")
        sys.exit(0)
