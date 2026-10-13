from scapy.all import sniff, IP, TCP
import time

WINDOW = 10
THRESHOLD = 15
COOLDOWN = 30
seen = {}
alerted = {}


def handle(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP].src
    port = pkt[TCP].dport
    now = time.time()

    if str(pkt[TCP].flags) == "S":
        if ip not in seen:
            seen[ip] = {}
        seen[ip][port] = now
        fresh = {}
        for p, t in seen[ip].items():
            if now - t <= WINDOW:
                fresh[p] = t
            seen[ip] = fresh
        last = alerted.get(ip)
        if len(seen[ip]) > THRESHOLD and (last is None or now - last > COOLDOWN):
            print("ALERT: possible port scan from", ip,"-",  len(seen[ip]), "different ports")
            alerted[ip] = now
    
    
sniff(prn=handle, store=False, iface="lo")

