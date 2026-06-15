#!/usr/bin/env python3
import json
import sys
import os

def load_manifest(filepath):
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        # Parse content as JSON
        content = "".join(lines)
        manifest = json.loads(content)
        return lines, manifest
    except Exception as e:
        print(f"ERROR: Failed to load manifest file {filepath}: {e}")
        sys.exit(1)

def find_violation_line(lines, module_name, search_key):
    # Find where the module block starts
    module_start = -1
    for idx, line in enumerate(lines):
        if f'"{module_name}"' in line:
            module_start = idx
            break
            
    if module_start == -1:
        return 1 # Default to line 1 if module not found
        
    # Search from module start for the key
    for idx in range(module_start, len(lines)):
        line = lines[idx]
        if f'"{search_key}"' in line:
            return idx + 1
            
    return module_start + 1

def format_github_annotation(severity, filepath, line, title, message):
    # GitHub Action annotation format: ::error file={name},line={line},title={title}::{message}
    gh_severity = "error" if severity in ["HIGH", "CRITICAL"] else "warning"
    print(f"::{gh_severity} file={filepath},line={line},title={title}::{message}")

def scan_manifest(filepath):
    lines, manifest = load_manifest(filepath)
    
    modules = manifest.get("modulesContent", {}).get("$edgeAgent", {}).get("properties.desired.modules", {})
    if not modules:
        print("No modules found in the deployment manifest.")
        return 0

    violations_count = 0
    failed = False
    
    print("\n" + "="*80)
    print(f"AlignAV Manifest Security Scan: {filepath}")
    print("="*80)
    
    in_github_actions = os.environ.get('GITHUB_ACTIONS') == 'true'

    for name, config in modules.items():
        print(f"\nScanning Module: {name} ...")
        image = config.get("settings", {}).get("image", "")
        create_options = config.get("settings", {}).get("createOptions", {})
        host_config = create_options.get("HostConfig", {})
        
        # Extract properties
        privileged = host_config.get("Privileged", False)
        readonly = host_config.get("ReadonlyRootfs", False)
        user = host_config.get("User", "root")
        
        # Rules definition
        # 1. Unsigned Image check (image name must contain "signed")
        is_signed = "signed" in image.split(":")[-1] if ":" in image else False
        if not is_signed:
            violations_count += 1
            line = find_violation_line(lines, name, "image")
            rule_name = "Container Image Unsigned"
            desc = f"Module '{name}' uses unsigned image '{image}'. Container images should be signed using Cosign."
            print(f"  [CRITICAL] {rule_name}: {desc} (Line {line})")
            if in_github_actions:
                format_github_annotation("CRITICAL", filepath, line, rule_name, desc)
            failed = True

        # 2. Privileged container check
        if privileged:
            violations_count += 1
            line = find_violation_line(lines, name, "Privileged")
            rule_name = "Privileged Mode Enabled"
            desc = f"Module '{name}' runs in privileged mode. This grants the container direct access to host resources."
            print(f"  [HIGH] {rule_name}: {desc} (Line {line})")
            if in_github_actions:
                format_github_annotation("HIGH", filepath, line, rule_name, desc)
            failed = True

        # 3. Non-root user check
        if user == "root" or user == "0" or user == "":
            violations_count += 1
            line = find_violation_line(lines, name, "User")
            rule_name = "Running as Root User"
            desc = f"Module '{name}' runs as root context. A non-root UID (e.g., 1000:1000) should be defined."
            print(f"  [HIGH] {rule_name}: {desc} (Line {line})")
            if in_github_actions:
                format_github_annotation("HIGH", filepath, line, rule_name, desc)
            failed = True

        # 4. Read-only root filesystem check
        if not readonly:
            violations_count += 1
            line = find_violation_line(lines, name, "ReadonlyRootfs")
            rule_name = "Writable Root Filesystem"
            desc = f"Module '{name}' has a writable root filesystem. HostConfig.ReadonlyRootfs should be set to true."
            print(f"  [MEDIUM] {rule_name}: {desc} (Line {line})")
            if in_github_actions:
                format_github_annotation("MEDIUM", filepath, line, rule_name, desc)
            # Medium issues might not fail the build depending on preference, but we'll flag it

    print("\n" + "="*80)
    if violations_count > 0:
        print(f"Scan complete: Found {violations_count} security violation(s).")
        print("="*80 + "\n")
        return 1 if failed else 0
    else:
        print("Scan complete: No security violations found! Code is aligned with security standards.")
        print("="*80 + "\n")
        return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scan_manifest.py <path_to_deployment.json>")
        sys.exit(1)
        
    exit_code = scan_manifest(sys.argv[1])
    sys.exit(exit_code)
