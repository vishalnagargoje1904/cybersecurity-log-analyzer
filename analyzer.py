import time
import argparse
import json
import os
from collections import defaultdict

# ---------------- ARGUMENTS ----------------
parser = argparse.ArgumentParser(description="Cybersecurity Log Analyzer")

parser.add_argument("logfiles", nargs="+", help="Log files to analyze")
parser.add_argument("--output", help="Output file (JSON format)")
parser.add_argument("--live", action="store_true", help="Enable real-time monitoring")
parser.add_argument("--block", action="store_true", help="Enable auto IP blocking")

args = parser.parse_args()

# ---------------- BLOCK FUNCTION ----------------
def block_ip(ip):
    confirm = input(f"⚠️ Do you want to block IP {ip}? (y/n): ")
    if confirm.lower() == "y":
        print(f"⛔ Blocking IP: {ip}")
        os.system(f"sudo ufw deny from {ip}")
    else:
        print(f"❌ Skipped blocking {ip}")

# ---------------- REAL-TIME FUNCTION ----------------
def monitor_file(filepath):
    print(f"\n📡 Monitoring {filepath} in real-time...\n")

    with open(filepath, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue

            if "FAILED" in line:
                parts = line.split()
                ip = parts[0]
                print(f"🚨 LIVE ALERT: Failed login from {ip}")

# ---------------- LIVE MODE ----------------
if args.live:
    for logfile in args.logfiles:
        monitor_file(logfile)
    exit()

# ---------------- NORMAL ANALYSIS ----------------
failed_attempts = defaultdict(int)
time_analysis = defaultdict(list)

for logfile in args.logfiles:
    with open(logfile, "r") as file:
        for line in file:
            if "FAILED" in line:
                parts = line.split()
                ip = parts[0]

                time_val = parts[3].split(":")[1] + ":" + parts[3].split(":")[2]

                failed_attempts[ip] += 1
                time_analysis[ip].append(time_val)

# ---------------- SORT ----------------
sorted_ips = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

# ---------------- REPORT ----------------
report_data = {
    "summary": [],
    "brute_force": [],
    "rapid_attack": []
}

print("\n🔍 Suspicious Activity Report:\n")

for ip, count in sorted_ips:
    print(f"IP: {ip} → Failed Attempts: {count}")
    report_data["summary"].append({"ip": ip, "attempts": count})

print("\n⚠️ Brute Force Detection:\n")

for ip, count in sorted_ips:
    if count >= 3:
        print(f"🚨 BRUTE FORCE ALERT: {ip} ({count} attempts)")
        report_data["brute_force"].append({"ip": ip, "attempts": count})

        # Auto blocking (if enabled)
        if args.block:
            block_ip(ip)

print("\n⏱️ Rapid Attack Detection:\n")

for ip, times in time_analysis.items():
    if len(times) >= 3:
        print(f"⚡ RAPID ATTACK from {ip}")
        report_data["rapid_attack"].append({"ip": ip})

# ---------------- SAVE JSON ----------------
if args.output:
    with open(args.output, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"\n📁 JSON report saved as {args.output}")
