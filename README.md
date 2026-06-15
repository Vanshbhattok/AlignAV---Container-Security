# AlignAV — Container Security Simulator & CI/CD Pipeline

This project replicates the security layer of an **Azure IoT Edge** gateway, featuring a local dashboard, simulated runtime threats, and a robust **GitHub Actions CI/CD security pipeline**.

---

## 🛠️ GitHub Actions CI/CD Security Pipeline

The `.yml`-based workflow is located at [container-security.yml](.github/workflows/container-security.yml). It automates container security scans, Dockerfile quality checks, and configuration audits.

### Key Pipeline Components:
1. **Python Linting (`flake8`)**: Automatically runs static analysis on python scripts to check code quality and detect runtime bugs.
2. **Dockerfile Linting (`hadolint`)**: Evaluates `Dockerfile` rules (e.g. root user check, base image pin check, package updates) using `hadolint/hadolint-action`.
3. **IoT Edge Manifest Audit (`scan_manifest.py`)**: A custom Python scanner that parses `deployment.json` for security anomalies:
   * **Root User Execution Check** (`HostConfig.User`)
   * **Privileged Container Check** (`HostConfig.Privileged`)
   * **Read-Write Root Filesystem Check** (`HostConfig.ReadonlyRootfs`)
   * **Unsigned ACR Image Tags** (looking for trusted `-signed` tags)
4. **Vulnerability & Secret Scanning (`trivy`)**: Executes Aqua Security's `trivy` engine to scan files, dependencies, and configurations for CVEs and hardcoded secrets.
5. **Interactive Diff Scans**: Generates and uploads a standard **SARIF** report to GitHub Code Scanning. This allows security findings to appear directly in the **"Files changed"** diff view of a pull request, creating an inline feedback loop.

---

## 🚀 How to Run the Local Simulation

To spin up the zero-cloud simulation environment locally:

1. **Terminal 1 — Start the Hub Service & Dashboard**:
   ```bash
   python3 mock_iot_hub.py
   ```
   * Open the dashboard in your browser: [http://localhost:8080](http://localhost:8080)

2. **Terminal 2 — Bootstrap the Edge Gateway Daemon**:
   ```bash
   python3 mock_edge_device.py
   ```
   * Performs virtual TPM 2.0 endorsement key attestation.
   * Downloads deployment manifest rules and checks image signatures.
   * Begins downstream sensor telemetry ingestion.

3. **Terminal 3 — Simulate Threats & Attacks**:
   Run CLI commands to trigger alerts on the dashboard in real-time:
   * **Host Escape Attempt**: `python3 mock_edge_device.py escape`
   * **Subnet Port Scan**: `python3 mock_edge_device.py portscan`
   * **Remediate / Re-secure**: `python3 mock_edge_device.py restore`

---

## 🛡️ Resolving Security Violations

To test a successful CI build, you can fix the security configuration errors in [deployment.json](deployment.json):

1. **User Privileges**: Change `"User": "root"` to a non-privileged UID like `"1000:1000"`.
2. **Privileged Mode**: Change `"Privileged": true` to `false` (in `HostConfig`).
3. **Read-only Root Filesystem**: Change `"ReadonlyRootfs": false` to `true` (in `HostConfig`).
4. **Image Signature**: Update the image from `custom-analytics:latest` to a secure, Cosign-signed tag version such as `custom-analytics:v1.0.0-signed`.
