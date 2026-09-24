from scapy.all import sniff


def get_flow_key(packet):
    if packet.haslayer("TCP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport
        protocol = packet["IP"].proto

        endpoint1 = (src_ip, src_port)
        endpoint2 = (dst_ip, dst_port)

        return tuple(sorted([endpoint1, endpoint2])) + (protocol,)


print("Starting packet capture...")

packets = sniff(count=5)

print(f"\nCaptured {len(packets)} packets\n")


flows = {}

for packet in packets:
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        flow = get_flow_key(packet)

        if flow not in flows:
            flows[flow] = []

        flows[flow].append(packet)


for flow, flow_packets in flows.items():

    total_bytes = sum(len(packet) for packet in flow_packets)

    start_time = min(packet.time for packet in flow_packets)
    end_time = max(packet.time for packet in flow_packets)

    flow_duration = end_time - start_time

    print("Flow:", flow)
    print("Number of packets:", len(flow_packets))
    print("Total bytes:", total_bytes)
    print("Flow duration:", flow_duration)
    print("--------------------")