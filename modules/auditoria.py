import dns.resolver, whois, requests, socket
from core.colors import G, R, W, C, Y
from core.utils import typewriter, save_report, sanitize_url

def dns_lookup():
    target = input(f"\n{G}Ingresa el dominio: {W}").strip()
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

def whois_lookup():
    target = input(f"\n{G}Ingresa el dominio a investigar: {W}").strip()
    if not target: return
    
    typewriter(f"{C}[+] Consultando WHOIS para: {target}...{W}")
    try:
        w = whois.whois(target)
        report_data = f"WHOIS Data for {target}\n\n"
        

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


def robots_txt():
    url_input = input(f"\n{G}Ingresa la URL base (ej: uca.edu): {W}").strip()
    if not url_input: return
    
    # Sanitiza para obtener la raiz del dominio
    clean_url = sanitize_url(url_input)
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

def save_report(tool_name, target, data):
    try:
        if not os.path.exists(REPORTS_DIR): os.makedirs(REPORTS_DIR)
        # ... resto del código
    except OSError as e:
        print(f"{R}[!] No se pudo guardar el reporte: {e}{W}")