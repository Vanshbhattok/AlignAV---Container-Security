#!/usr/bin/env python3
import json
import sys
import time
import urllib.request
import urllib.error
import threading

HUB_URL = "http://localhost:8080"
DEVICE_ID = "alignav-edge-gateway-01"
TPM_EK = "EK:00a12f33c09b88e144a1b0213ff032e1855a9e701bc23e"

# Global run flag
running = True

def post_to_hub(endpoint, payload):
    url = f"{HUB_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as res:
            if res.status == 204:
                return None
            return json.loads(res.read().decode("utf-8"))
    except urllib.error.URLError as e:
        print(f"\033[91m[Error]\033[0m Could not connect to Mock Hub: {e.reason}")
        return None

def start_telemetry():
    global running
    print("[Edge Device] Telemetry thread started. Ingesting downstream sensor data...")
    temp = 24.5
    while running:
        # Simulate temp readings
        temp += 0.2
        if temp > 35: temp = 24.5
        
        payload = {
            "device_id": DEVICE_ID,
            "payload": {
                "temperature": round(temp, 2),
                "humidity": 45,
                "status": "Healthy"
            }
        }
        
        post_to_hub("/devices/telemetry", payload)
        time.sleep(3)

def run_edge_agent():
    print(f"\033[94m[Booting]\033[0m Starting Azure IoT Edge Runtime daemon on host...")
    time.sleep(1)
    
    # 1. TPM Attestation Handshake
    print(f"\033[94m[Attestation]\033[0m Reading host TPM 2.0 endorsement key...")
    time.sleep(1)
    reg_res = post_to_hub("/devices/register", {
        "device_id": DEVICE_ID,
        "tpm_status": "Attested",
        "tpm_ek": TPM_EK
    })
    
    if not reg_res:
        print("\033[91m[Attestation Failed]\033[0m Dynamic Hub Assignment rejected by DPS security.")
        return
        
    print(f"\033[92m[Attested]\033[0m Device verified. Bound to dynamic Hub: \033[93m{reg_res['assigned_hub']}\033[0m")
    
    # 2. Retrieve Deployment Manifest
    print(f"\033[94m[Manifest]\033[0m Fetching deployment manifest from Cloud Hub...")
    time.sleep(1)
    
    manifest_url = f"{HUB_URL}/devices/deployment"
    try:
        with urllib.request.urlopen(manifest_url) as res:
            manifest = json.loads(res.read().decode("utf-8"))
    except Exception as e:
        print(f"\033[91m[Manifest Error]\033[0m Failed to retrieve deployment specifications: {e}")
        return
        
    modules = manifest.get("modulesContent", {}).get("$edgeAgent", {}).get("properties.desired.modules", {})
    running_modules = ["edgeAgent", "edgeHub"]
    
    print("\033[94m[Cosign Check]\033[0m Auditing registry signatures against trusted Key Vault keys...")
    time.sleep(1.5)
    
    for mod_name, mod_config in modules.items():
        image = mod_config.get("settings", {}).get("image", "")
        # Sign check
        is_signed = "v1.0.0-signed" in image
        
        if is_signed:
            print(f"  ✓ Signature verified for module \033[92m{mod_name}\033[0m (Image: {image})")
            running_modules.append(mod_name)
        else:
            print(f"  ✗ \033[91m[COSIGN ERROR]\033[0m Image signature verification failed for module \033[93m{mod_name}\033[0m (Image: {image})")
            # Log threat log to Hub and allow bypass startup for simulation purposes
            post_to_hub("/devices/security-alerts", {
                "device_id": DEVICE_ID,
                "module": mod_name,
                "severity": "CRITICAL",
                "message": f"Deployment Warning: Module image '{image}' lacks a trusted, validated Cosign signature in ACR. Startup bypassed for execution evaluation.",
                "action": "BYPASS_STARTUP"
            })
            running_modules.append(mod_name)
            time.sleep(0.5)
            
    # Send running modules list to hub
    post_to_hub("/devices/update-modules", {
        "device_id": DEVICE_ID,
        "modules": running_modules
    })
    
    # Start telemetry loop
    t = threading.Thread(target=start_telemetry, daemon=True)
    t.start()
    
    print(f"\033[92m[Ready]\033[0m Gateway online. Running containers list: {running_modules}")
    print("Edge runtime running. Keep this process alive. To simulate security incidents, open another terminal window and run CLI commands.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Edge Runtime daemon...")
        global running
        running = False
        sys.exit(0)

# CLI Triggers
def trigger_alert(attack_type):
    if attack_type == "escape":
        payload = {
            "device_id": DEVICE_ID,
            "module": "customAnalyticsModule",
            "severity": "HIGH",
            "message": "Defender for IoT: Host escape attempt detected. Container attempted to write unauthorized mount files directly to host kernel directories.",
            "action": "ISOLATE"
        }
        print("\033[91m[Alert Trigger]\033[0m Simulating container host escape attempt...")
    elif attack_type == "portscan":
        payload = {
            "device_id": DEVICE_ID,
            "module": "customAnalyticsModule",
            "severity": "HIGH",
            "message": "Defender for IoT: Subnet discovery port scan. Anomalous volume attempted network mapping of local on-premises network.",
            "action": "ISOLATE"
        }
        print("\033[91m[Alert Trigger]\033[0m Simulating container-led network port scan...")
    elif attack_type == "restore":
        payload = {
            "device_id": DEVICE_ID,
            "module": "customAnalyticsModule",
            "severity": "INFO",
            "message": "Security Incident Resolved. Vulnerable module updated, namespaces re-secured, and networks restored.",
            "action": "RESTORE"
        }
        print("\033[92m[Restore Trigger]\033[0m Simulating remediation and security restore...")
    else:
        print("Invalid attack parameter. Use: escape, portscan, restore")
        return

    # To trigger alert, we send it to mock hub.
    # If it is a restore, we clear the hub's alert list!
    if attack_type == "restore":
        # Clear alerts by requesting the server (we let server clear alerts list)
        req = urllib.request.Request(f"{HUB_URL}/devices/security-alerts", data=json.dumps({"clear": True}).encode("utf-8"), headers={"Content-Type": "application/json"})
        # Actually, let's just make the server handle POST with 'action': 'RESTORE' as a signal to clear list
        post_to_hub("/devices/security-alerts", {
            "device_id": DEVICE_ID,
            "module": "customAnalyticsModule",
            "severity": "INFO",
            "message": "Audit completed. Insecure containers removed. Clean configuration deployed.",
            "action": "RESTORE"
        })
    else:
        post_to_hub("/devices/security-alerts", payload)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        trigger_alert(cmd)
    else:
        run_edge_agent()
