import argparse
from collections import defaultdict

parser = argparse.ArgumentParser(description="Cybersecurity Log Analyzer")
parser.add_argument("logfiles", nargs="+", help="Log files to analyze")
args = parser.parse_args()

failed_attempts = defaultdict(int)
time_analysis = defaultdict(list)

for logfile in args.logfiles:
    with open(logfile, "r") as file:
        for line in file:
            if "FAILED" in line:
                parts = line.split()
                ip = parts[0]

                time = parts[3].split(":")[1] + ":" + parts[3].split(":")[2]

                failed_attempts[ip] += 1
                time_analysis[ip].append(time)

sorted_ips = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

print("\n🔍 Suspicious Activity Report:\n")

for ip, count in sorted_ips:
    print(f"IP: {ip} → Failed Attempts: {count}")

print("\n⚠️ Brute Force Detection:\n")

for ip, count in sorted_ips:
    if count >= 3:
        print(f"🚨 BRUTE FORCE ALERT: {ip} ({count} attempts)")

print("\n⏱️ Rapid Attack Detection:\n")

for ip, times in time_analysis.items():
    if len(times) >= 3:
        print(f"⚡ RAPID ATTACK from {ip}")
