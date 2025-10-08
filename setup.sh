#!/bin/bash

# Exit on any error
set -e

# Variables
SYS_MON_DIR="/opt/sysmon"
VENV_DIR="$SYS_MON_DIR/env"
SERVICE_FILE="/etc/systemd/system/sysmon-beat.service"
PYTHON_SCRIPT="$SYS_MON_DIR/sysmon_json.py"

echo "Step 1: Creating virtual environment..."
python3 -m venv "$VENV_DIR"

echo "Step 2: Activating virtual environment and installing lxml..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install lxml
deactivate


cat > /opt/sysmon/sysmon_json.py <<EOF
import asyncio
import logging
import re
from typing import Dict, Optional, Any
from lxml import etree
import json
import socket
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class SysmonConfig:
    """Manage configuration settings."""
    def __init__(self):
        self.filter_rule_names = ["-", ""]
        self.output_format = "json"
        self.tcp_host = "127.0.0.1"
        self.tcp_port = 12515
        self.reconnect_interval = 5  # Seconds to wait before reconnecting

def extract_event_fields(element: etree.Element) -> Optional[Dict[str, Any]]:
    """
    Extract Timestamp, Hostname, and Message from Sysmon <Event>.
    """
    try:
        result = {}

        # Extract Timestamp
        time_created = element.xpath("./System/TimeCreated")[0]
        result["Timestamp"] = time_created.get("SystemTime") or \
            element.xpath(".//Data[@Name='UtcTime']/text()")[0].strip()

        # Extract Hostname
        computer = element.xpath("./System/Computer")[0]
        result["Hostname"] = computer.text.strip() if computer.text else ""

        # Extract Message (all EventData fields as dict)
        message = {}
        for data in element.xpath("./EventData/Data"):
            name = data.get("Name")
            value = data.text.strip() if data.text else ""
            if name:
                message[name] = value
        result["Message"] = message

        return result
    except (IndexError, AttributeError) as e:
        logger.error(f"Error extracting event fields: {e}")
        return None

async def send_to_tcp(data: str, config: SysmonConfig) -> bool:
    """Send data to TCP endpoint with reconnection logic."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # Set timeout for connection
            sock.connect((config.tcp_host, config.tcp_port))
            # Send JSON data with newline terminator
            sock.sendall((data + '\n').encode('utf-8'))
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.error(f"TCP send attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {config.reconnect_interval} seconds...")
                await asyncio.sleep(config.reconnect_interval)
        finally:
            if 'sock' in locals():
                sock.close()
    logger.error("Failed to send data to TCP endpoint after retries")
    return False

async def process_buffer(buffer: str, config: SysmonConfig) -> str:
    """Process complete <Event> blocks and send to TCP endpoint."""
    events = re.findall(r'<Event>.*?</Event>', buffer, re.DOTALL)
    for ev in events:
        try:
            parser = etree.XMLParser(recover=True)
            root = etree.fromstring(ev, parser=parser)
            event_data = extract_event_fields(root)
            if not event_data:
                continue

            # Apply RuleName filter
            rule_name = event_data.get("Message", {}).get("RuleName", "")
            if rule_name in config.filter_rule_names:
                continue

            # Output in specified format
            if config.output_format == "json":
                json_data = json.dumps(event_data)
                success = await send_to_tcp(json_data, config)
                if not success:
                    logger.warning(f"Failed to send event: {json_data}")
            else:
                logger.warning(f"Unsupported output format: {config.output_format}")
        except etree.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            continue

    # Keep leftover partial XML in buffer
    last_end = 0
    for m in re.finditer(r'</Event>', buffer):
        last_end = m.end()
    return buffer[last_end:]

async def stream_sysmon_logs(config: SysmonConfig) -> None:
    """Stream sysmon logs and output to TCP endpoint."""
    cmd = ["journalctl", "-u", "sysmon", "-f", "-o", "cat"]
    buffer = ""

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        while True:
            try:
                line = (await process.stdout.readline()).decode('utf-8')
                if not line:  # EOF
                    break
                buffer += line
                buffer = await process_buffer(buffer, config)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing log line: {e}")
                continue

        await process.wait()
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error: {e}")
    finally:
        if 'process' in locals():
            process.terminate()

async def main():
    """Main entry point for the sysmon log processor."""
    config = SysmonConfig()
    await stream_sysmon_logs(config)

if __name__ == "__main__":
    asyncio.run(main())
EOF

echo "Step 3: Creating systemd service file..."
cat <<EOF | sudo tee "$SERVICE_FILE" > /dev/null
[Unit]
Description=SysMon JSON Monitoring Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sysmon
ExecStart=/opt/sysmon/env/bin/python3 /opt/sysmon/sysmon_json.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "Step 4: Reloading systemd, enabling and starting service..."
sudo systemctl daemon-reload
sudo systemctl enable sysmon-beat.service
sudo systemctl start sysmon-beat.service

echo "✅ Sysmon service installed and started successfully!"
sudo systemctl status sysmon-beat.service --no-pager

