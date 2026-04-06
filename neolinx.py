import os
import sys
import time
import socket
import requests
import platform
import dns.resolver
import whois
import re
from threading import Thread

# === CONFIGURACION DE COLORES Y ESTILO ===
G, R, W, C, M, Y = '\033[1;32m', '\033[1;31m', '\033[0m', '\033[1;36m', '\033[1;35m', '\033[1;33m'

# Carpeta oculta para guardar reportes
REPORTS_DIR = ".neolinx_reports"
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

def clear():
    os.system("clear" if platform.system() == "Linux" else "cls")

def typewriter(text, delay=0.005):
    for char in text + '\n':
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

# === GUARDADO DE REPORTES ===
def save_report(tool_name, target, data):
    # Reemplaza caracteres invalidos para nombres de archivo
    safe_target = re.sub(r'[^\w\s-]', '_', target).strip().lower()
    timestamp = time.strftime("%Y%m%d_%H%M")
    filepath = os.path.join(REPORTS_DIR, f"{safe_target}_{tool_name}_{timestamp}.txt")
    
    with open(filepath, "w") as f:
        f.write(f"--- NeoLinx v3.1 Report: {tool_name} ---\n")
        f.write(f"Target: {target}\nDate: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 40 + "\n\n")
        f.write(data)
    
    print(f"\n{Y}[i] Reporte guardado en: {filepath}{W}")

# === SANITIZACION DE URLS ===
def sanitize_url(url, require_protocol=True):
    url = url.strip()
    if not url: return None
    
    # Maneja la omision del protocolo
    if require_protocol and not re.match(r'^https?://', url):
        typewriter(f"{Y}[i] Aviso: No se detecto protocolo. Usando http:// por defecto.{W}")
        url = 'http://' + url
    
    domain_match = re.search(r'^https?://([^/?#:]+)', url)
    if domain_match: return domain_match.group(1)
    
    return url

# =============================
# === MODULOS DE AUDITORIA  ===
# =============================

# --- [01] DNS Lookup ---
def dns_lookup():
    target = input(f"\n{G}Ingresa el dominio (ej: uca.edu): {W}").strip()
    if not target: return
    
    tipos = ['A', 'MX', 'NS', 'TXT']
    report_data = f"DNS Records for {target}\n\n"
    typewriter(f"{C}[+] Consultando registros DNS para: {target}...{W}")
    
    found_any = False
    for tipo in tipos:
        try:
            respuestas = dns.resolver.resolve(target, tipo)
            print(f"\n{G}--- Registros {tipo} ---{W}")
            report_data += f"--- {tipo} ---\n"
            for rdata in respuestas:
                print(f" {rdata}")
                report_data += f" {rdata}\n"
            found_any = True
        except dns.resolver.NoAnswer: continue
        except dns.resolver.NXDOMAIN:
            print(f"{R}[!] Dominio no encontrado.{W}")
            return
        except Exception as e:
            print(f"{R}[!] Error en {tipo}: {e}{W}")
            report_data += f" Error en {tipo}: {e}\n"
            
    if not found_any: print(f"{Y}[-] No se encontraron registros publicos.{W}")
    save_report("DNS", target, report_data)

# --- [02] Whois Lookup ---
def whois_lookup():
    target = input(f"\n{G}Ingresa el dominio a investigar: {W}").strip()
    if not target: return
    
    typewriter(f"{C}[+] Consultando WHOIS para: {target}...{W}")
    try:
        w = whois.whois(target)
        report_data = f"WHOIS Data for {target}\n\n"
        
        # Estructura limpia para el reporte y la pantalla
        info = [
            ("Registrador", w.registrar),
            ("Creacion", w.creation_date),
            ("Expiracion", w.expiration_date),
            ("Organizacion", w.org),
            ("Pais", w.country),
            ("Emails Contacto", w.emails)
        ]
        
        print(f"\n{G}--- Datos Legales del Dominio ---{W}")
        for label, value in info:
            if value:
                # Formatea fechas si son listas
                if isinstance(value, list): value = ", ".join(map(str, value))
                print(f"{C}{label}:{W} {value}")
                report_data += f"{label}: {value}\n"
        
        save_report("WHOIS", target, report_data)
        
    except Exception as e:
        print(f"{R}[!] Error en WHOIS (posible bloqueo o dominio .edu.gt): {e}{W}")

# --- [03] GeoIP Lookup ---
def geo_ip():
    target = input(f"\n{G}Ingresa la IP o Dominio: {W}").strip()
    if not target: return
    
    typewriter(f"{C}[+] Localizando objetivo...{W}")
    try:
        response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
        data = response.json()
        
        if data.get('status') == 'fail':
            print(f"{R}[!] Error en la API: {data.get('message')}{W}")
            return

        report_data = f"GeoIP Data for {target}\n\n"
        info = [
            ("Pais", data.get('country')),
            ("Ciudad", data.get('city')),
            ("ISP", data.get('isp')),
            ("IP Real", data.get('query')),
            ("Lat/Lon", f"{data.get('lat')}, {data.get('lon')}")
        ]
        
        print(f"\n{G}--- Ubicacion Geografica ---{W}")
        for label, value in info:
            print(f"{C}{label}:{W} {value}")
            report_data += f"{label}: {value}\n"
            
        save_report("GeoIP", target, report_data)
        
    except Exception as e:
        print(f"{R}[!] Error al conectar con la API: {e}{W}")

# --- [04] HTTP Header ---
def http_header():
    url_input = input(f"\n{G}Ingresa la URL (ej: uca.edu): {W}").strip()
    if not url_input: return
    
    # Sanitiza la URL para requests
    clean_url = sanitize_url(url_input, require_protocol=True)
    typewriter(f"{C}[+] Analizando cabeceras de: {clean_url}...{W}")
    
    try:
        response = requests.get(clean_url, timeout=10)
        headers = response.headers
        report_data = f"HTTP Headers for {clean_url}\nStatus: {response.status_code}\n\n"
        
        print(f"\n{G}--- Cabeceras HTTP (Status: {response.status_code}) ---{W}")
        for header, value in headers.items():
            print(f"{C}{header}:{W} {value}")
            report_data += f"{header}: {value}\n"
            
        save_report("HEADERS", clean_url, report_data)
        
    except requests.exceptions.MissingSchema:
        print(f"{R}[!] URL Invalida. Asegurate de incluir el protocolo (http/https).{W}")
    except Exception as e:
        print(f"{R}[!] Error al conectar: {e}{W}")

# === PORT SCANNER CON HILOS (THREADING) ===
port_results = []
def scan_worker(ip, port):
    global port_results
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0) # Un segundo por puerto es suficiente con hilos
    result = sock.connect_ex((ip, port))
    if result == 0:
        port_results.append((port, "ABIERTO", G))
    else:
        port_results.append((port, "CERRADO", R))
    sock.close()

def port_scanner():
    global port_results
    port_results = [] # Limpia resultados anteriores
    target = input(f"\n{G}Ingresa la IP o Dominio a escanear: {W}").strip()
    if not target: return
    
    # Puertos mas comunes e importantes en auditorias
    puertos = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080]
    typewriter(f"{C}[+] Escaneando {len(puertos)} puertos criticos en: {target}...{W}")
    
    try:
        ip = socket.gethostbyname(target)
        print(f"{C}[i] IP resuelta: {ip}{W}\n")
        
        threads = []
        # Crea y lanza un hilo por cada puerto (Concurrencia masiva)
        for puerto in puertos:
            t = Thread(target=scan_worker, args=(ip, puerto))
            threads.append(t)
            t.start()
            
        # Espera a que todos los hilos terminen
        for t in threads:
            t.join()
            
        # Ordena y muestra los resultados
        port_results.sort()
        report_data = f"Port Scan for {target} ({ip})\n\n"
        for port, status, color in port_results:
            print(f"{color}[*] Puerto {port}:\t{status}{W}")
            report_data += f"Puerto {port}: {status}\n"
            
        save_report("PORTSCAN", target, report_data)
        
    except socket.gaierror:
        print(f"{R}[!] Error: No se pudo resolver el host.{W}")
    except Exception as e:
        print(f"{R}[!] Error en el escaneo: {e}{W}")

# --- [06] Robots.txt ---
def robots_txt():
    url_input = input(f"\n{G}Ingresa la URL base (ej: uca.edu): {W}").strip()
    if not url_input: return
    
    # Sanitiza para obtener la raiz del dominio
    clean_url = sanitize_url(url_input, require_protocol=True)
    if clean_url.endswith('/'): clean_url = clean_url[:-1]
    
    final_url = f"{clean_url}/robots.txt"
    typewriter(f"{C}[+] Buscando archivo en: {final_url}...{W}")
    
    try:
        response = requests.get(final_url, timeout=10)
        if response.status_code == 200:
            print(f"\n{G}--- Contenido de robots.txt ---{W}\n")
            print(response.text)
            save_report("ROBOTS", clean_url, response.text)
        else:
            print(f"{R}[-] No se encontro el archivo (Status: {response.status_code}){W}")
    except Exception as e:
        print(f"{R}[!] Error de conexion: {e}{W}")

# --- [07] Subdomain Finder ---
def subdomain_finder():
    target = input(f"\n{G}Ingresa el dominio principal (ej: uca.edu.gt): {W}").strip()
    if not target: return
    
    # Lista de subdominios comunes (Administrativo: se puede expandir)
    subdominios = ['www', 'mail', 'ftp', 'admin', 'cpanel', 'webmail', 'blog', 'dev', 'test', 'api']
    typewriter(f"{C}[+] Buscando {len(subdominios)} subdominios comunes para: {target}...{W}")
    
    encontrados = 0
    print(f"\n{G}--- Resultados ---{W}")
    report_data = f"Subdomain Scan for {target}\n\n"
    
    for sub in subdominios:
        url = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(url)
            print(f"{G}[+] Existe:{W} {url} {C}(IP: {ip}){W}")
            report_data += f"{url} -> {ip}\n"
            encontrados += 1
        except socket.gaierror: pass
            
    if encontrados == 0:
        print(f"{R}[-] No se encontraron subdominios comunes.{W}")
        report_data += "No subdomains found.\n"
    
    save_report("SUBDOMAINS", target, report_data)

# --- MENU PRINCIPAL ---
def menu():
    clear()
    print(f"""{M}
    _   __              __    _             _____   ____
   / | / /___  ____    / /   (_)____ __  __/|__  /  / / /
  /  |/ / _ \/ __ \  / /   / / __ \\| |/_/ /_ <  / / / 
 / /|  /  __/ /_/ / / /___/ / / / />  <  ___/ / /_/ /  
/_/ |_/\___/\____/ /_____/_/_/ /_/_/|_| /____/ \____/   v3.1

{G}==== Reconnaissance Suite by Linx (Admin Edition) ===={W}
""")
    print(f"""
{C}[01]{W} DNS Lookup
{C}[02]{W} Whois Lookup
{C}[03]{W} GeoIP Locator
{C}[04]{W} HTTP Header Analyzer
{C}[05]{W} Port Scanner
{C}[06]{W} Robots.txt Scraper
{C}[07]{W} Subdomain Finder
{C}[00]{W} Salir
    """)

# --- LOGICA DE CONTROL (OPTIMIZADA) ---
def run():
    funciones = {
        "01": dns_lookup, "02": whois_lookup, "03": geo_ip,
        "04": http_header, "05": port_scanner, "06": robots_txt,
        "07": subdomain_finder
    }
    
    while True:
        menu()
        opcion = input(f"{G}NeoLinx >> {W}").strip()
        
        if opcion == "00":
            print(f"\n{R}[!] Apagando Sentinel. ¡Nos vemos¡,{W}")
            break
        elif opcion in funciones:
            funciones[opcion]()
        else:
            print(f"\n{R}[!] Opcion no valida.{W}")
            
        if opcion != "00":
            input(f"\n{M}[Presiona ENTER para volver al menu central...]{W}")

if __name__ == "__main__":
    run()