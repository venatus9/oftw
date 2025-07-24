import os
import json
import subprocess
import logging
import ipaddress
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "data.json")

SUSPICIOUS_PORTS = {6667, 31337, 4444, 5555, 12345, 27374, 31338}
SUSPICIOUS_EXTENSIONS = {".dmg", ".sh", ".command", ".app", ".py", ".pl", ".rb", ".exe", ".jar"}
# Directories to scan for suspicious files
WATCHED_DIRS = [
    "/tmp",
    "/var/tmp",
    os.path.expanduser("~/Library/Application Support"),
    os.path.expanduser("~/Downloads"),
]

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast)
    except ValueError:
        return False

def parse_lsof():
    """
    Run 'lsof -i' to get network connections and parse suspicious endpoints.
    """
    try:
        logging.info("Running lsof to get network connections...")
        output = subprocess.check_output(["lsof", "-i", "-n", "-P"], text=True)
    except Exception as e:
        logging.error(f"Failed to run lsof: {e}")
        return []

    suspicious_endpoints = []

    lines = output.strip().split("\n")
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue

        command = parts[0]
        pid = parts[1]
        user = parts[2]
        name = parts[-1]

        if "->" not in name:
            continue

        local_part, remote_part = name.split("->")
        remote_ip_port = remote_part.split(" ")[0]
        if ":" not in remote_ip_port:
            continue

        remote_ip, remote_port_str = remote_ip_port.rsplit(":", 1)
        try:
            remote_port = int(remote_port_str)
        except ValueError:
            continue

        if is_public_ip(remote_ip) or remote_port in SUSPICIOUS_PORTS:
            suspicious_endpoints.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "process": command,
                "pid": pid,
                "user": user,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "connection": name
            })

    return suspicious_endpoints

def check_suspicious_files():
    """
    Scan WATCHED_DIRS for recently created suspicious files.
    """
    suspicious_files = []
    now = datetime.now()
    lookback = now - timedelta(days=1)  # last 1 day

    for directory in WATCHED_DIRS:
        if not os.path.exists(directory):
            continue

        logging.info(f"Scanning directory for suspicious files: {directory}")

        # Use find command to list files modified in last 1 day
        try:
            cmd = ["find", directory, "-type", "f", "-mtime", "-1", "-print"]
            output = subprocess.check_output(cmd, text=True)
            files = output.strip().split("\n")
        except Exception as e:
            logging.error(f"Failed to scan directory {directory}: {e}")
            continue

        for filepath in files:
            if not filepath:
                continue
            _, ext = os.path.splitext(filepath.lower())

            if ext in SUSPICIOUS_EXTENSIONS or any(s in filepath.lower() for s in ["temp", "tmp", "update", "install", "launch"]):
                try:
                    stat = os.stat(filepath)
                    ctime = datetime.fromtimestamp(stat.st_ctime)
                    if ctime < lookback:
                        # Ignore files older than lookback anyway
                        continue
                except Exception:
                    ctime = None

                suspicious_files.append({
                    "timestamp": ctime.isoformat() + "Z" if ctime else None,
                    "filepath": filepath,
                    "extension": ext,
                })

    return suspicious_files

def save_data_to_json(data, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    logging.info(f"Saved data to {filepath}")

def main():
    network_suspicious = parse_lsof()
    file_suspicious = check_suspicious_files()

    all_suspicious = {
        "network_suspicious_endpoints": network_suspicious,
        "suspicious_files_created": file_suspicious,
    }

    if network_suspicious or file_suspicious:
        logging.info(f"Found {len(network_suspicious)} suspicious network endpoints and {len(file_suspicious)} suspicious files.")
    else:
        logging.info("No suspicious network endpoints or file creations found.")

    save_data_to_json(all_suspicious, OUTPUT_FILE)

if __name__ == "__main__":
    main()
