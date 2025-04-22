import csv
import subprocess
import os
import requests
from datetime import datetime


SHODAN_API_KEY = 'shodan_api_key'  # Uzupełnij kluczem API Shodan
VT_API_KEY = 'virustotal_api_key'  # Uzupełnij kluczem API VirusTotal

# Wykonanie skanowania nmap
def scan_ports(ip):
    nmap_command = f"nmap -sS -T2 --max-rate 5 -p 3389,5900,5901 {ip}"
    result = subprocess.run(nmap_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8')

# Uzyskanie informacji o hoście z Shodan
def get_shodan_info(ip):
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Błąd uzyskiwania danych z Shodan: {e}")
        return None

# Uzyskanie informacji o IP z VirusTotal
def get_virustotal_info(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Błąd uzyskiwania danych z VirusTotal: {e}")
        return None

# Wykonanie zapytania o konfigurację VNC
def check_vnc(ip, port):
    nc_command = f"nc -nv {ip} {port}"
    result = subprocess.run(nc_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8') if result.returncode == 0 else None

# Odczyt danych z pliku CSV i skanowanie
def scan_datacenters(csv_file, output_file):
    with open(csv_file, mode='r') as file:
        reader = csv.reader(file)
        next(reader)

        with open(output_file, mode='w') as outfile:
            outfile.write(f"Raport skanowania - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            for row in reader:
                name, ip = row
                print(f"Skanowanie: {name} | {ip}")
                results = f"ADRES IP: {ip} | NAZWA: {name}\nNMAP:\n"

                # Skanowanie portów
                nmap_result = scan_ports(ip)
                print(f"Wynik NMAP dla {ip}: \n{nmap_result}")
                results += nmap_result + "\n"

                # Informacje z Shodan
                shodan_info = get_shodan_info(ip)
                if shodan_info:
                    results += "Informacje z Shodan:\n"
                    results += f"Organization: {shodan_info.get('org', 'Brak informacji')}\n"
                    results += f"Asn: {shodan_info.get('asn', 'Brak informacji')}\n"
                    results += f"City: {shodan_info.get('city', 'Brak informacji')}\n"
                    results += f"Country: {shodan_info.get('country_name', 'Brak informacji')}\n"
                    results += f"Last Update: {shodan_info.get('last_update', 'Brak informacji')}\n\n"

                # Informacje z VirusTotal
                vt_info = get_virustotal_info(ip)
                if vt_info and "data" in vt_info:
                    results += "Informacje z VirusTotal:\n"
                    attributes = vt_info["data"].get("attributes", {})
                    results += f"Reputation: {attributes.get('reputation', 'Brak')}\n"
                    results += f"Harmless votes: {attributes.get('last_analysis_stats', {}).get('harmless', 'Brak')}\n"
                    results += f"Malicious votes: {attributes.get('last_analysis_stats', {}).get('malicious', 'Brak')}\n"
                    results += f"Suspicious votes: {attributes.get('last_analysis_stats', {}).get('suspicious', 'Brak')}\n"
                    results += f"Undetected votes: {attributes.get('last_analysis_stats', {}).get('undetected', 'Brak')}\n\n"

                # Sprawdzenie VNC
                if "5900/tcp open" in nmap_result or "5901/tcp open" in nmap_result:
                    if "5900/tcp open" in nmap_result:
                        vnc_result_5900 = check_vnc(ip, 5900)
                        if vnc_result_5900:
                            results += "Dane konfiguracji VNC (5900):\n" + vnc_result_5900

                    if "5901/tcp open" in nmap_result:
                        vnc_result_5901 = check_vnc(ip, 5901)
                        if vnc_result_5901:
                            results += "Dane konfiguracji VNC (5901):\n" + vnc_result_5901

                results += "\n"
                outfile.write(results)


scan_datacenters('ip_list.csv', 'wyniki_skanowania.txt')
