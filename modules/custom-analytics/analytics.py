#!/usr/bin/env python3
import time

print("[Insecure Analytics] Booting module as user: root...")
print("[Insecure Analytics] WARNING: Running with full system privileges. Mounting host rootfs is possible.")

try:
    while True:
        print("[Insecure Analytics] Harvesting local telemetry and logs...")
        time.sleep(10)
except KeyboardInterrupt:
    print("[Insecure Analytics] Stopping...")
