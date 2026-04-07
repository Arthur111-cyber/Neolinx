import socket
from threading import Thread, Lock
from core.colors import G, R, W, C, Y
from core.utils import typewriter, save_report, is_valid_input

# Mapeo de servicios comunes para auditoría
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 443: "HTTPS", 
    445: "SMB", 3306: "MySQL", 8080: "HTTP-Alt"
}

def scan_worker(ip, port, results_lock, results_list):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    result = sock.connect_ex((ip, port))
    
    with results_lock:
        status = ("ABIERTO", G) if result == 0 else ("CERRADO", R)
        results_list.append((port, status[0], status[1]))
    sock.close()

def port_scanner():
    local_results, local_lock = [], Lock()
    
    target = input(f"\n{G}Ingresa la IP o Dominio: {W}").strip()
    
    # [1] VALIDACIÓN DE ENTRADA
    if not is_valid_input(target):
        return print(f"{R}[!] Error: Caracteres no permitidos en el objetivo.{W}")
    
    puertos = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 8080]
    typewriter(f"{C}[+] Iniciando escaneo de {len(puertos)} puertos criticos...{W}")
    
    try:
        ip = socket.gethostbyname(target)
        threads = []
        
        for i, puerto in enumerate(puertos):
            # [2] BARRA DE PROGRESO (Usa \r para sobreescribir la misma línea)
            print(f"\r{Y}[i] Progreso: {i+1}/{len(puertos)} puertos analizados...{W}", end="")
            
            t = Thread(target=scan_worker, args=(ip, puerto, local_lock, local_results))
            threads.append(t)
            t.start()
            
        for t in threads: t.join()
        print("\n") # Salto de línea después de la barra de progreso
            
        local_results.sort()
        report_data = f"Port Scan for {target} ({ip})\n\n"
        
        for port, status, color in local_results:
            # [3] IDENTIFICACIÓN DE SERVICIO
            service = SERVICES.get(port, "Unknown")
            print(f"{color}[*] Puerto {port} ({service}):\t{status}{W}")
            report_data += f"Puerto {port} ({service}): {status}\n"
            
        save_report("PORTSCAN", target, report_data)
        
    except Exception as e:
        print(f"\n{R}[!] Error en el escaneo: {e}{W}")