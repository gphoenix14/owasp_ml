import subprocess
import csv
import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw

# Argparse per specificare la porta
parser = argparse.ArgumentParser(description='Capture HTTP requests on a specified port')
parser.add_argument('-p', '--port', type=int, required=True, help='Port to capture HTTP traffic')
args = parser.parse_args()

# File CSV di output
output_file = 'http_requests.csv'

# Creare l'intestazione del file CSV
with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['datetime', 'ip_src', 'src_port', 'endpoint', 'query', 'payload'])

# Funzione per analizzare i pacchetti HTTP
def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            # Decodificare il payload HTTP
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            if 'HTTP' in payload:
                # Estrazione delle informazioni
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ip_src = packet[IP].src
                src_port = packet[TCP].sport

                # Identificazione GET/POST e estrazione dei dati
                if 'GET' in payload:
                    endpoint = payload.split(' ')[1].split('?')[0]
                    query = payload.split('?')[1].split(' ')[0] if '?' in payload else ''
                    post_payload = ''
                elif 'POST' in payload:
                    endpoint = payload.split(' ')[1]
                    query = ''
                    post_payload = payload.split('\r\n\r\n')[1] if '\r\n\r\n' in payload else ''
                else:
                    return

                # Scrittura nel file CSV
                with open(output_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, ip_src, src_port, endpoint, query, post_payload])

                # Stampa sul terminale
                print(f"[{timestamp}] {ip_src}:{src_port} {endpoint} {query} {post_payload}")

        except Exception as e:
            print(f"Error processing packet: {e}")

# Avviare tcpdump per catturare i pacchetti HTTP sulla porta specificata
def start_sniffing():
    filter_str = f"tcp port {args.port} and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"
    print(f"Starting tcpdump on port {args.port}...")
    
    sniff(filter=filter_str, prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
