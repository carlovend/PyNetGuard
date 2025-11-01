import queue
import time
import threading
import logging
from scapy.all import sniff, IP, TCP, Raw 
import requests  
import os        
import json      
from dotenv import load_dotenv  

load_dotenv()
DASHBOARD_API_URL = "http://127.0.0.1:8000/api/receive_alerts"
alert_queue = queue.Queue()

syn_tracker = {} 
SYN_FLOOD_THRESHOLD = 100 
SYN_FLOOD_TIMEFRAME = 5   


SUSPICIOUS_PORTS = {21, 22, 23, 445, 3389} # FTP, SSH, Telnet, SMB, RDP


logging.basicConfig(
    filename="alerts.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

def process_packet(packet):
    
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    try:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
    except IndexError:
        return

    # controlla solo i pacchetti SYN (Flag 'S' == 0x02)
    if flags == 0x02:
        now = time.time()
        
        #inizializza o recupera la lista di timestamp per questo IP
        timestamps = syn_tracker.setdefault(src_ip, [])
        
        # aggiungi l'ora corrente
        timestamps.append(now)
        
       
        # mantiene solo quelli negli ultimi 5 secondi
        syn_tracker[src_ip] = [t for t in timestamps if now - t < SYN_FLOOD_TIMEFRAME]
        
        # controlla se abbiamo superato la soglia
        if len(syn_tracker[src_ip]) > SYN_FLOOD_THRESHOLD:
            # Metti in coda l'allarme
            details = f"Oltre {SYN_FLOOD_THRESHOLD} SYN in {SYN_FLOOD_TIMEFRAME}s"
            alert_queue.put(('SYN Flood', src_ip, dst_port, details))
            
            # resetta il tracker per questo IP per evitare spam di allarmi
            syn_tracker[src_ip] = []
            
        # un pacchetto SYN è solo per il tracker, quindi usciamo
        return 

    # stateless null scan
    elif flags == 0x00:
        alert_queue.put(('Null Scan', src_ip, dst_port, 'Flags=0x00'))
        return # pacchetto gestito

    # xmas Scan stateless
    elif flags == 0x29: # Flag FIN, PSH, URG
        alert_queue.put(('Xmas Scan', src_ip, dst_port, 'Flags=FPU'))
        return # pacchetto gestito
        
    
    # questa regola scatta solo se il pacchetto ha un payload
    elif packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load).lower()
            
            # cerca potenziale SQL Injection
            if b"select" in payload and (b"from" in payload or b"where" in payload):
                alert_queue.put(('Potenziale SQL Injection', src_ip, dst_port, 'Rilevato "SELECT...FROM/WHERE"'))
                return
            
            # cerca potenziale Directory Traversal
            elif b"get /etc/passwd" in payload:
                alert_queue.put(('Potenziale Directory Traversal', src_ip, dst_port, 'Rilevato "/etc/passwd"'))
                return
                
        except Exception:
            # ignora errori di parsing del payload
            pass

    
    # questa scatta solo se nessuna delle regole più specifiche sopra è scattata
    elif dst_port in SUSPICIOUS_PORTS:
        alert_queue.put(('Porta Sospetta', src_ip, dst_port, f"Tentativo su porta {dst_port}"))
        return # pacchetto gestito


def alert_worker():
    """
    Questo è il Worker potenziato a "Investigatore".
    Prende gli allarmi dalla coda, li arricchisce con VirusTotal
    e salva i risultati.
    """
    
    
    VT_API_KEY = os.getenv("VT_API_KEY")
    if not VT_API_KEY:
        print("Errore: VT_API_KEY non impostata. L'enricher non partirà.")
        return 

    vt_headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }
    
    print("Worker 'Investigatore' (API) avviato. In attesa di lavoro...")
    
    while True:
        try:
            # prende l'allarme dalla coda
            reason, src_ip, dst_port, details = alert_queue.get()
            
            
            
            # non arricchire IP privati (risparmia quote API)
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
                        vt_summary = f"VT Score: Malicious={malicious}, Suspicious={suspicious}"
                    
                    elif response.status_code == 429: # rate Limit
                        vt_summary = "VT Rate Limit (rallento)"
                        print("[WORKER] Rate limit API raggiunto. Attendo 60s...")
                        time.sleep(60)
                    else: # 404 (non trovato) o altri errori
                        vt_summary = f"VT Errore: {response.status_code}"
                
                except requests.RequestException as e:
                    vt_summary = f"Errore di rete: {e}"
                    
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
    
    # avvia il thread (inizia a girare in background)
    worker_thread.start()

    # avvia lo sniffer (nel thread principale)
    print("Avvio di NetSentry... (Premi Ctrl+C per fermare)")
    
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("Errore: Esegui lo script come amministratore (sudo) per catturare i pacchetti.")
    except KeyboardInterrupt:
        print("\nChiusura di NetSentry.")