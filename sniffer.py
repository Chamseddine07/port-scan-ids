from scapy.all import sniff, IP, TCP

seen = {}
alerted = set()

def handle(pkt):
    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP].src
    port = pkt[TCP].dport

    if str(pkt[TCP].flags) == "S":
        if ip not in seen:
            seen[ip] = set()
        seen[ip].add(port)
        if len(seen[ip]) > 15 and ip not in alerted:
            print("ALERT: possible port scan from", ip,"-",  len(seen[ip]), "different ports")
            alerted.add(ip)
    
    
sniff(prn=handle, store=False, iface="lo")

