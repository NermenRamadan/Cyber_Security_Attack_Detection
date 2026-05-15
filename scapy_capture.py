import time
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS
import uuid

def get_device_id():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                     for ele in range(0, 8*6, 8)][::-1])

DEVICE_ID = get_device_id()
print(f"Device ID: {DEVICE_ID}")

API_URL = "http://127.0.0.1:8000/predict"


MY_USER_ID = "8b891a60-f2ca-4609-a926-a1510abd6d03" 

FEATURE_NAMES = [
    'deltatime', 'ip_flag_df', 'TCP Window Size', 'is_browser',
    'ip_flag_none', 'tcp_rst', 'is_attack_tool',
    'TCP Acknowledgment Number', 'is_http_1_0', 'has_dns_query',
    'TCP Sequence Number', 'TCP Destination Port', 'Length',
    'is_http_error', 'tcp_psh', 'TCP Stream', 'is_script',
    'is_http_response', 'TCP Source Port', 'HTTP Content-Length'
]

last_time = [time.time()]
tcp_stream_counter = {}
stream_id = [0]

def extract_features(pkt):
    now = time.time()
    deltatime = now - last_time[0]
    last_time[0] = now

    length = len(pkt)

    # IP flags
    ip_flag_df = 0
    ip_flag_none = 0
    if IP in pkt:
        flags = int(pkt[IP].flags)
        ip_flag_df = 1 if flags & 0x02 else 0
        ip_flag_none = 1 if flags == 0 else 0

    # TCP
    tcp_window = 0
    tcp_rst = 0
    tcp_psh = 0
    tcp_seq = 0
    tcp_ack_num = 0
    tcp_dst_port = 0
    tcp_src_port = 0
    tcp_stream = 0

    if TCP in pkt:
        tcp_window    = int(pkt[TCP].window)
        tcp_flags     = int(pkt[TCP].flags)
        tcp_rst       = 1 if tcp_flags & 0x04 else 0
        tcp_psh       = 1 if tcp_flags & 0x08 else 0
        tcp_seq       = int(pkt[TCP].seq)
        tcp_ack_num   = int(pkt[TCP].ack)
        tcp_dst_port  = int(pkt[TCP].dport)
        tcp_src_port  = int(pkt[TCP].sport)

        # simulate TCP stream id
        key = (pkt[IP].src, pkt[IP].dst, tcp_src_port, tcp_dst_port)
        if key not in tcp_stream_counter:
            stream_id[0] += 1
            tcp_stream_counter[key] = stream_id[0]
        tcp_stream = tcp_stream_counter[key]

    # DNS
    has_dns_query = 1 if DNS in pkt else 0

    # HTTP features
    is_http_response  = 0
    is_http_1_0       = 0
    is_http_error     = 0
    http_content_len  = 0
    is_attack_tool    = 0
    is_browser        = 0
    is_script         = 0

    if TCP in pkt and Raw in pkt:
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')

            # HTTP version
            if 'HTTP/1.0' in payload:
                is_http_1_0 = 1

            # HTTP response
            if payload.startswith('HTTP/'):
                is_http_response = 1
                # error codes 4xx, 5xx
                parts = payload.split(' ')
                if len(parts) >= 2:
                    code = parts[1]
                    if code.startswith('4') or code.startswith('5'):
                        is_http_error = 1

            # Content-Length
            if 'Content-Length:' in payload:
                try:
                    cl = payload.split('Content-Length:')[1].split('\r\n')[0].strip()
                    http_content_len = int(cl)
                except:
                    pass

            # User-Agent detection
            payload_lower = payload.lower()
            if any(t in payload_lower for t in ['sqlmap', 'nmap', 'nikto', 'hydra', 'metasploit', 'ffuf', 'masscan']):
                is_attack_tool = 1
            if any(t in payload_lower for t in ['mozilla', 'chrome', 'firefox', 'safari', 'edge']):
                is_browser = 1
            if any(t in payload_lower for t in ['python', 'curl', 'wget', 'requests', 'go-http']):
                is_script = 1

        except:
            pass

    features = [
        deltatime,       # deltatime
        ip_flag_df,      # ip_flag_df
        tcp_window,      # TCP Window Size
        is_browser,      # is_browser
        ip_flag_none,    # ip_flag_none
        tcp_rst,         # tcp_rst
        is_attack_tool,  # is_attack_tool
        tcp_ack_num,     # TCP Acknowledgment Number
        is_http_1_0,     # is_http_1_0
        has_dns_query,   # has_dns_query
        tcp_seq,         # TCP Sequence Number
        tcp_dst_port,    # TCP Destination Port
        length,          # Length
        is_http_error,   # is_http_error
        tcp_psh,         # tcp_psh
        tcp_stream,      # TCP Stream
        is_script,       # is_script
        is_http_response,# is_http_response
        tcp_src_port,    # TCP Source Port
        http_content_len # HTTP Content-Length
    ]

    return features

def process_packet(pkt):
    if IP not in pkt:
        return
    try:
        features = extract_features(pkt)
    
        response = requests.post(
            API_URL,
            json={
                "features": features,
                "user_id": MY_USER_ID,
                "source_ip": pkt[IP].src,
                "device_id": DEVICE_ID,
            },
            timeout=5
        )
        result = response.json()
        confidence = result.get("confidence")
        conf_str = f"{confidence*100:.1f}%" if confidence is not None else "N/A"

        if result.get("is_attack"):
            print(f"ATTACK | {result['attack_type']} | {result['severity']} | Confidence: {conf_str} | src: {pkt[IP].src}")
        else:
            print(f"Normal | Confidence: {conf_str} | src: {pkt[IP].src}")

    except Exception as e:
        print(f"Error: {e}")

print("Starting Scapy capture... Press Ctrl+C to stop")
sniff(filter="ip", prn=process_packet, store=0)