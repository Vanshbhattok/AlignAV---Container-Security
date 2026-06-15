#!/usr/bin/env python3
import time
import random

print("[Secure Temp Sensor] Starting up...")
print("[Secure Temp Sensor] Initialization successful. Generating random telemetry...")

try:
    while True:
        # Simulate temp readings
        temperature = round(random.uniform(22.0, 28.0), 2)
        humidity = round(random.uniform(40.0, 50.0), 2)
        
        print(f"[Telemetry] Temp: {temperature}°C | Humidity: {humidity}% | Status: Healthy")
        time.sleep(5)
except KeyboardInterrupt:
    print("[Secure Temp Sensor] Exiting cleanly...")
