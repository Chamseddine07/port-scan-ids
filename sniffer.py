from scapy.all import sniff, IP, TCP

def handle(pkt):
    if IP not in pkt or TCP not in pkt:
        return 
    print(pkt[IP].src, pkt[IP].dst, pkt[TCP].dport, pkt[TCP].flags)
    
    
sniff(prn=handle, store=False)

