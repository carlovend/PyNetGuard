# PyNetGuard: Python Network Intrusion Detection System

PyNetGuard is a lightweight, high-performance network intrusion detection system (IDS) written in Python. It is designed to capture and analyze network traffic in real-time, detect various forms of malicious activity, and enrich alerts with external threat intelligence.

The system is built on a high-throughput, asynchronous architecture to ensure that packet sniffing is not blocked by slower I/O operations like logging or API calls.

---

## Features

### Core Architecture
* **Real-time Packet Sniffing:** Captures and analyzes TCP packets live from a specified network interface using `scapy`.
* **Multi-Threaded Processing:** Utilizes a two-thread model (sniffer + worker) to prevent packet loss.
    * **Sniffer Thread:** Performs rapid, in-memory detection and places potential threats onto a `queue`.
    * **Worker Thread:** Consumes alerts from the queue to perform slower operations (logging, API calls, and file I/O) without blocking the sniffer.

### Detection Engine
* **Stateless Detection:**
    * **Stealth Scan Detection:** Identifies `Null Scans` (TCP Flags `0x00`) and `Xmas Scans` (TCP Flags `FIN`, `PSH`, `URG`).
    * **Port Monitoring:** Flags connection attempts to a defined list of suspicious ports (e.g., 21, 22, 23, 445, 3389).

* **Stateful Detection:**
    * **SYN Flood Detection:** Tracks the rate of `SYN` packets from source IPs, triggering an alert if a threshold is breached within a set timeframe.

* **Deep Packet Inspection (DPI):**
    * **Potential SQL Injection:** Detects common `SELECT...FROM` patterns in packet payloads.
    * **Potential Directory Traversal:** Detects attempts to access common sensitive files (e.g., `/etc/passwd`).

### Threat Intelligence & Logging
* **API Enrichment:** Automatically queries the VirusTotal API for the reputation of public source IPs associated with an alert.
* **Secure API Key Management:** Uses a `.env` file and `python-dotenv` to manage API keys securely.
* **Dual Logging:**
    * `alerts.log`: A human-readable log of all detected alerts.
    * `alerts_enriched.jsonl`: A machine-readable JSON-Lines file containing structured data for each alert, including the full VirusTotal enrichment.

---

## Getting Started

### Prerequisites
* Python 3.8+
* `pip` and `venv`
* Administrative (e.g., `sudo`) privileges to run the packet sniffer.
* A VirusTotal API Key.

### Installation
1.  Clone the repository:
    ```bash
    git clone [https://github.com/your-username/PyNetGuard.git](https://github.com/your-username/PyNetGuard.git)
    cd PyNetGuard
    ```

2.  Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    *(You will need to create a `requirements.txt` file containing `scapy`, `requests`, and `python-dotenv`)*

### Configuration
1.  Create a file named `.env` in the root of the project directory.
2.  Add your VirusTotal API key to this file:
    ```
    VT_API_KEY="your_virustotal_api_key_here"
    ```

### Usage
Run the script with administrative privileges:
```bash
sudo python PyNetGuard.py
```

### Testing Environment
Due to kernel-level network optimizations (especially on macOS and some Linux distributions), **testing by scanning `localhost` or your own local IP from the same machine will not work.** The kernel will short-circuit the packets, and they will not be visible to Scapy.

To test the IDS, you must use a **separate machine** on the same network (e.g., a virtual machine in "Bridged Adapter" mode) to launch scans (e.g., `nmap -sN <your_host_ip>`) against the machine running `netsentry.py`.

---

## Roadmap (Work in Progress)

The following features are planned for future development to expand the project's capabilities:

* **Real-Time Web Dashboard**
    * Develop a Flask or FastAPI backend to serve alert data via a REST API or WebSockets.
    * Build a simple HTML/JavaScript frontend to visualize incoming alerts in real-time, creating a proper Security Operations Center (SOC) dashboard.

* **Active Response (IPS Functionality)**
    * Implement an "active response" module.
    * Upon detecting a high-confidence threat (e.g., a SYN flood or an IP with a high malicious score), the system will automatically execute a command to add a temporary firewall rule (e.g., via `iptables`) to block the offending IP.

* **Database Persistence**
    * Migrate from file-based `.jsonl` logging to a more robust `sqlite3` database.
    * This will allow for persistent storage and enable more complex, historical querying of alerts (e.g., "show all attacks from this IP in the last 30 days").

* **External Rule Configuration**
    * Move hard-coded rules (suspicious ports, DPI strings, SYN flood thresholds) to an external `config.yaml` file.
    * This will allow users to modify detection parameters without editing the Python source code.