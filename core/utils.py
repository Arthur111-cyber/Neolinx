import os, sys, time, re, platform, json, ipaddress
from core.colors import Y, W, R

REPORTS_DIR = ".neolinx_reports"

def clear():
    os.system("clear" if platform.system() == "Linux" else "cls")

def typewriter(text, delay=0.005):
    for char in text + '\n':
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

def is_valid_input(target):
    if not target or " " in target: return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(re.match(r'^[a-zA-Z0-9\-\.]+$', target))

def sanitize_url(url):
    url = url.strip()
    if not url: return None
    if not re.match(r'^https?://', url): url = 'http://' + url
    match = re.search(r'^(https?://[^/?#:]+)', url)
    return match.group(1) if match else url

def save_report(tool_name, target, data):
    if not os.path.exists(REPORTS_DIR): os.makedirs(REPORTS_DIR)
    safe_target = re.sub(r'[^\w\s-]', '_', target).strip().lower()
    filepath = os.path.join(REPORTS_DIR, f"{safe_target}_{tool_name}_{time.strftime('%Y%m%d_%H%M')}.txt")
    with open(filepath, "w") as f:
        f.write(f"--- NeoLinx v3.2.1 Report: {tool_name} ---\nTarget: {target}\n" + "-"*40 + "\n\n" + data)
    print(f"\n{Y}[i] Reporte TXT guardado en: {filepath}{W}")

def save_report_json(tool_name, target, data_dict):
    if not os.path.exists(REPORTS_DIR): os.makedirs(REPORTS_DIR)
    safe_target = re.sub(r'[^\w\s-]', '_', target).strip().lower()
    filepath = os.path.join(REPORTS_DIR, f"{safe_target}_{tool_name}.json")
    with open(filepath, "w") as f:
        json.dump(data_dict, f, indent=4)
    print(f"{Y}[i] Reporte JSON guardado en: {filepath}{W}")