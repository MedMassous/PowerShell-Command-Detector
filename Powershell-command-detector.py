#!/usr/bin/env python3
"""
PowerShell Command Detector
---------------------------
A beginner-friendly blue team tool that scans Windows-style log files
and flags suspicious PowerShell usage based on simple detection rules.


Author: Mohamed Massous
"""

from collections import Counter

LOG_FILE = "logs.txt"
OUTPUT_FILE = "alerts.txt"

SUSPICIOUS_KEYWORDS = [
    "Invoke-Expression",
    "IEX",
    "DownloadString",
    "FromBase64String",
    "EncodedCommand",
    "-enc",
    "Invoke-WebRequest",
    "curl",
    "wget",
    "New-Object System.Net.WebClient",]

def extract_value(line, key):
    if f"{key}=" in line:
        return line.split(f"{key}=")[1].strip()
    return "N/A"

def detect_powershell_commands(log_file):
    alerts = []
    keyword_hits = Counter()
    try:
        with open(log_file,"r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()
                if "powershell" in line.lower():
                    command = extract_value(line, "CommandLine")
                    for keyword in SUSPICIOUS_KEYWORDS:
                        if keyword.lower() in command.lower():
                            alert = (
                                f"[Alert !] Line {line_number}: "
                                f"Suspicious PowerShell usage detected | "
                                f"Keyword: {keyword} | Command: {command}"
                                                            )
                            alerts.append(alert)
                            keyword_hits[keyword] += 1
        return alerts, keyword_hits
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        return [], Counter()
    
def save_alerts(alerts, stats):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write("PowerShell Command Detection Report\n")
        file.write("="*40 + "\n\n")

        if alerts:
            for alert in alerts:
                file.write(alert + "\n")
        else:
            file.write("No suspicious PowerShell activity detected.\n")
        file.write("\nDetection Statistics:\n")
        for keyword, count in stats.items():
            file.write(f"{keyword}: {count} hits\n")

def main():
    print("[+] Starting PowerShell Command Detection...")
    alerts, stats = detect_powershell_commands(LOG_FILE)
    save_alerts(alerts, stats)
    print(f"[+] Detection complete. Alerts saved to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    main()