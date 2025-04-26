import subprocess
import socket
import requests
import dns.resolver
import whois
import json
import ssl

def enumerate_subdomains(domain):
    try:
        result = subprocess.check_output(['amass', 'enum', '-d', domain])
        subdomains = result.decode().split('\n')
        return [s.strip() for s in subdomains if s.strip()]
    except:
        return []

def live_subdomains(subdomains):
    alive = []
    for sub in subdomains:
        try:
            r = requests.get(f"http://{sub}", timeout=3)
            if r.status_code:
                alive.append(sub)
        except:
            continue
    return alive

def get_dns_records(domain):
    records = {}
    try:
        records['A'] = [r.address for r in dns.resolver.resolve(domain, 'A')]
    except: pass
    try:
        records['MX'] = [r.exchange.to_text() for r in dns.resolver.resolve(domain, 'MX')]
    except: pass
    try:
        records['NS'] = [r.to_text() for r in dns.resolver.resolve(domain, 'NS')]
    except: pass
    return records

def port_scan(domain):
    try:
        result = subprocess.check_output(['nmap', '-sV', '-T4', '-p-', domain])
        return result.decode()
    except:
        return "Nmap scan failed"

def ssl_analysis(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert
    except:
        return "SSL analysis failed"

def whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except:
        return {}
