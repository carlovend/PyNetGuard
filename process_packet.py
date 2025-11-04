import queue
import time
import threading
import logging
import subprocess
import platform  #per multiOs
import requests
import os
import json
from scapy.all import sniff, IP, TCP, Raw
from dotenv import load_dotenv


load_dotenv()
DASHBOARD_API_URL = "http://127.0.0.1:8000/api/receive_alerts"
VT_API_KEY = os.getenv("VT_API_KEY")


alert_queue = queue.Queue()
syn_tracker = {}
blocked_ips = set() # memoria per non bloccare IP già bloccati


SYN_FLOOD_THRESHOLD = 100
SYN_FLOOD_TIMEFRAME = 5
SUSPICIOUS_PORTS = {21, 22, 23, 445, 3389}
VT_BLOCK_THRESHOLD = 3 

# Configurazione Logging
logging.basicConfig(
    filename="alerts.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)



def block_ip(ip_to_block):
    """
    Esegue un comando firewall per bloccare un IP,
    in base al sistema operativo.
    """
    if ip_to_block in blocked_ips:
        print(f"[IPS] IP {ip_to_block} è già stato bloccato.")
        return

    os_name = platform.system()
    cmd = []

    print(f"[IPS] TENTATIVO DI BLOCCO: {ip_to_block} su {os_name}")

    if os_name == "Linux":
        cmd = ["iptables", "-I", "INPUT", "1", "-s", ip_to_block, "-j", "DROP"]
    elif os_name == "Windows":
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=NetSentry Block {ip_to_block}",
            "dir=in", "action=block", f"remoteip={ip_to_block}"
        ]
    elif os_name == "Darwin": # macOS
        print(f"[IPS] Rilevato macOS. Il blocco automatico di {ip_to_block} non è supportato.")
        return # difficile da fare poi si vede
    else:
        print(f"[IPS] Sistema operativo {os_name} non supportato per il blocco.")
        return

    try:
        subprocess.run(cmd, check=True, timeout=5, capture_output=True, text=True)
        print(f"[IPS] SUCCESSO: IP {ip_to_block} bloccato.")
        blocked_ips.add(ip_to_block)
    except FileNotFoundError:
        print(f"[IPS] ERRORE: Comando firewall non trovato.")
    except subprocess.CalledProcessError as e:
        print(f"[IPS] ERRORE: Permessi insufficienti o comando fallito. {e.stderr}")
    except Exception as e:
        print(f"[IPS] ERRORE SCONOSCIUTO: {e}")



def process_packet(packet):
    """
    Analizza i pacchetti e mette gli allarmi in coda.
    Progettato per essere il più veloce possibile.
    """
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    try:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
    except IndexError:
        return # pacchetto malformato

    #rilevamento SYN Flood (Stateful)
    if flags == 0x02: # Flag SYN
        now = time.time()
        timestamps = syn_tracker.setdefault(src_ip, [])
        timestamps.append(now)
        syn_tracker[src_ip] = [t for t in timestamps if now - t < SYN_FLOOD_TIMEFRAME]
        
        if len(syn_tracker[src_ip]) > SYN_FLOOD_THRESHOLD:
            details = f"Oltre {SYN_FLOOD_THRESHOLD} SYN in {SYN_FLOOD_TIMEFRAME}s"
            alert_queue.put(('SYN Flood', src_ip, dst_port, details))
            syn_tracker[src_ip] = [] 
        return

    #null Scan (Stateless)
    elif flags == 0x00:
        alert_queue.put(('Null Scan', src_ip, dst_port, 'Flags=0x00'))
        return

    #Xmas Scan (Stateless)
    elif flags == 0x29: # Flag FIN, PSH, URG
        alert_queue.put(('Xmas Scan', src_ip, dst_port, 'Flags=FPU'))
        return
        
    #DPI Semplice (Ispezione Payload)
    elif packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load).lower()
            if b"select" in payload and (b"from" in payload or b"where" in payload):
                alert_queue.put(('Potenziale SQL Injection', src_ip, dst_port, 'Rilevato "SELECT...FROM/WHERE"'))
                return
            elif b"get /etc/passwd" in payload:
                alert_queue.put(('Potenziale Directory Traversal', src_ip, dst_port, 'Rilevato "/etc/passwd"'))
                return
        except Exception:
            pass # Ignora errori di parsing

    #Porta Sospetta (Bassa Priorità)
    elif dst_port in SUSPICIOUS_PORTS:
        alert_queue.put(('Porta Sospetta', src_ip, dst_port, f"Tentativo su porta {dst_port}"))
        return



def alert_worker():
    """
    Prende allarmi dalla coda, li arricchisce (VT),
    esegue l'azione IPS (blocco) e invia al dashboard.
    """
    if not VT_API_KEY:
        print("Errore: VT_API_KEY non impostata. L'enricher non partirà.")
        return

    vt_headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
    print("✅ Worker 'IPS' (API + Firewall) avviato. In attesa di lavoro...")
    
    while True:
        try:
            reason, src_ip, dst_port, details = alert_queue.get()
            
            
            if reason == 'SYN Flood':
                block_ip(src_ip) #tenta il blocco immediato inutile che si fa analizzare

            
            malicious_score = 0
            if src_ip.startswith(('192.168.', '10.', '127.')):
                vt_summary = "IP Privato (non analizzato)"
            else:
                print(f"[WORKER] Chiamo VirusTotal per l'IP: {src_ip}")
                vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{src_ip}"
                try:
                    response = requests.get(vt_url, headers=vt_headers, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        malicious_score = malicious
                        vt_summary = f"VT Score: Malicious={malicious}, Suspicious={suspicious}"
                    elif response.status_code == 429:
                        vt_summary = "VT Rate Limit (rallento)"
                        print("[WORKER] Rate limit API raggiunto. Attendo 60s...")
                        time.sleep(60)
                    else:
                        vt_summary = f"VT Errore: {response.status_code}"
                except requests.RequestException as e:
                    vt_summary = f"Errore di rete: {e}"
            
           
            if malicious_score > VT_BLOCK_THRESHOLD:
                block_ip(src_ip) #blocco basato sullo score

           
            console_msg = f"ALLARME: {reason} da {src_ip} -> {dst_port} (Dettagli: {details}) [VT: {vt_summary}]"
            logging.warning(console_msg)
            print(f"[WORKER] {console_msg}")
            
            enriched_log_entry = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "alert_reason": reason,
                "source_ip": src_ip,
                "dest_port": dst_port,
                "details": details,
                "virustotal_summary": vt_summary
            }
            
            with open("alerts_enriched.jsonl", "a") as f:
                f.write(json.dumps(enriched_log_entry) + "\n")
            
            try:
                requests.post(DASHBOARD_API_URL, json=enriched_log_entry, timeout=2)
                print(f"[WORKER] Allarme inviato al dashboard.")
            except requests.RequestException as e:
                print(f"[WORKDASH] Errore invio al dashboard: {e}")

        except Exception as e:
            print(f"Errore grave nel worker: {e}")
        finally:
           alert_queue.task_done()



def main():
    worker_thread = threading.Thread(target=alert_worker, daemon=True)
    worker_thread.start()
    print("Avvio di NetSentry... (Premi Ctrl+C per fermare)")
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("Errore: Esegui lo script come amministratore (sudo / Esegui come Amministratore).")
    except KeyboardInterrupt:
        print("\nChiusura di NetSentry.")