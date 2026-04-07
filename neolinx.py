import sys
from core.colors import G, R, W, C, M, show_banner
from core.utils import clear
from modules.auditoria import (
    dns_lookup, whois_lookup, geo_ip, 
    http_header, robots_txt, subdomain_finder
)
from modules.port_scanner import port_scanner

def menu():
    clear()
    show_banner()
    print(f"""
{C}[01]{W} DNS Lookup           {C}[05]{W} Port Scanner
{C}[02]{W} Whois Lookup         {C}[06]{W} Robots.txt Scraper
{C}[03]{W} GeoIP Locator        {C}[07]{W} Subdomain Finder
{C}[04]{W} HTTP Header Analyzer {C}[00]{W} Salir
    """)

def run():
    # Diccionario que mapea opciones a las funciones importadas
    funciones = {
        "01": dns_lookup, "02": whois_lookup, "03": geo_ip,
        "04": http_header, "05": port_scanner, "06": robots_txt,
        "07": subdomain_finder
    }
    
    while True:
        menu()
        opcion = input(f"{G}NeoLinx >> {W}").strip()
        
        if opcion == "00":
            print(f"\n{R}[!] Apagando Sentinel. ¡Nos vemos!{W}")
            break
        elif opcion in funciones:
            funciones[opcion]()
        else:
            print(f"\n{R}[!] Opcion no valida.{W}")
            
        input(f"\n{M}[Presiona ENTER para volver al menu central...]{W}")

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Operación interrumpida.{W}")
        sys.exit()