from scapy.all import IP , TCP , UDP , Raw , sniff

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        transport_layer = None

        print("Packet:")
        print("Source IP: ", ip_layer.src)
        print("Destination IP: ", ip_layer.dst)
        
        if packet.haslayer(TCP):
            transport_layer = packet.getlayer(TCP)
            print("Protocol: TCP")
        elif packet.haslayer(UDP):
            transport_layer = packet.getlayer(UDP)
            print("Protocol: UDP")
        else:
            print("Protocol: Other")

        if transport_layer is not None:
            print("Source port: ", transport_layer.sport)
            print("Destination port: ", transport_layer.dport)
        
        if packet.haslayer(Raw):
            print("Payload:")
            print(packet[Raw].load)

        print('\n')

sniff(prn=packet_callback, store=0)
