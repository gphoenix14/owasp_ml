import subprocess
import csv
import argparse
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw

# Caricare il file di configurazione config.json
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# Argparse per specificare la porta
parser = argparse.ArgumentParser(description='Capture HTTP requests on a specified port')
parser.add_argument('-p', '--port', type=int, required=True, help='Port to capture HTTP traffic')
args = parser.parse_args()

# File CSV di output
output_file = 'http_requests.csv'

# Preprocesso dei campi attivi nel file di configurazione
enabled_fields = {key: value for key, value in config["fields"].items() if value}

# Creare l'intestazione del file CSV basato sui campi attivi
csv_headers = list(enabled_fields.keys())

with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(csv_headers)

# Pre-calcolare quali campi devono essere estratti
capture_datetime = 'datetime' in enabled_fields
capture_ip_src = 'ip_src' in enabled_fields
capture_src_port = 'src_port' in enabled_fields
capture_http_method = 'http_method' in enabled_fields
capture_endpoint = 'endpoint' in enabled_fields
capture_query = 'query' in enabled_fields
capture_payload = 'payload' in enabled_fields
capture_referer = 'referer' in enabled_fields
capture_user_agent = 'user_agent' in enabled_fields
capture_cookie = 'cookie' in enabled_fields

# Funzione per analizzare i pacchetti HTTP
def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            # Decodificare il payload HTTP
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            if 'HTTP' in payload:
                # Creare una riga vuota con valori dinamici
                row = []

                # Estrazione delle informazioni
                if capture_datetime:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    row.append(timestamp)

                if capture_ip_src:
                    ip_src = packet[IP].src
                    row.append(ip_src)

                if capture_src_port:
                    src_port = packet[TCP].sport
                    row.append(src_port)

                # Analisi della richiesta HTTP
                lines = payload.split('\r\n')
                request_line = lines[0] if len(lines) > 0 else ''
                parts = request_line.split(' ')
                http_method = parts[0] if len(parts) > 0 else ''
                uri = parts[1] if len(parts) > 1 else ''

                if capture_http_method:
                    row.append(http_method)

                if capture_endpoint:
                    endpoint = uri.split('?')[0] if uri else ''
                    row.append(endpoint)

                if capture_query:
                    query = uri.split('?', 1)[1] if '?' in uri else ''
                    row.append(query)

                if capture_payload:
                    post_payload = payload.split('\r\n\r\n',1)[1] if 'POST' in http_method and '\r\n\r\n' in payload else ''
                    row.append(post_payload)

                # Analisi degli header HTTP
                headers = {}
                for header_line in lines[1:]:
                    if ': ' in header_line:
                        key, value = header_line.split(': ', 1)
                        headers[key] = value

                if capture_referer:
                    referer = headers.get('Referer', '')
                    row.append(referer)

                if capture_user_agent:
                    user_agent = headers.get('User-Agent', '')
                    row.append(user_agent)

                if capture_cookie:
                    cookie = headers.get('Cookie', '')
                    row.append(cookie)

                # Scrittura nel file CSV
                with open(output_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(row)

                # Stampa sul terminale
                print(f"Captured HTTP request: {row}")

        except Exception as e:
            print(f"Error processing packet: {e}")

# Avviare lo sniffing per catturare i pacchetti HTTP sulla porta specificata
def start_sniffing():
    filter_str = f"tcp port {args.port} and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"
    print(f"Starting sniffing on port {args.port}...")
    
    sniff(filter=filter_str, prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
