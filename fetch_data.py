import os
import json
import subprocess
import logging
import ipaddress
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "data.json")

# Define suspicious ports often used by malware/trojans (example)
SUSPICIOUS_PORTS = {6667, 31337, 4444, 5555, 12345, 27374, 31338}

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
    header = lines[0]
    cols = header.split()
    # Typical columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    # We'll focus on COMMAND, PID, USER, NAME (last column has IP:port info)

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue

        command = parts[0]
        pid = parts[1]
        user = parts[2]
        name = parts[-1]  # format like TCP 192.168.1.5:56789->198.51.100.23:80 (ESTABLISHED)

        # Extract remote IP and port from NAME if possible
        # Example: TCP 192.168.1.5:56789->198.51.100.23:80 (ESTABLISHED)
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

        # Check if remote_ip is public and port is suspicious
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

def save_data_to_json(data, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    logging.info(f"Saved {len(data)} suspicious endpoints to {filepath}")

def main():
    suspicious_data = parse_lsof()
    if suspicious_data:
        logging.info(f"Found {len(suspicious_data)} suspicious network endpoints.")
        save_data_to_json(suspicious_data, OUTPUT_FILE)
    else:
        logging.info("No suspicious network endpoints found.")

if __name__ == "__main__":
    main()

