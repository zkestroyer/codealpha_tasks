## network sniffer
## dowmload npcap and reboot
## download scapy through pip


from scapy.all import sniff, IP, TCP, UDP, ICMP,Raw


def analyze_network(packet):
    try:
        print("#"*50)

        if IP in packet:
            ip=packet[IP]
            print(f"[ip] {ip.src} Source -> Destination {ip.dst}")

            if TCP in packet:
                tcp=packet[TCP]
                print(f"[tcp] {tcp.sport} Source port -> Destination port {tcp.dport} ")
            
            if UDP in packet:
                Udp=packet[UDP]
                print(f"[udp] {Udp.sport} Source port -> Destination port {Udp.dport} ")
            
            if ICMP in packet:
                icmp=packet[ICMP]
                print(f"[icmp] {icmp.type} Type -> Code {icmp.code} ")
            
        if Raw in packet:
            Data=packet[Raw]
            print(f"[Raw] payload_data->{Data.load[:50]}")
    except Exception as e:
        print(f"Error processing packet: {e}")


sniff(prn=analyze_network,store=0)