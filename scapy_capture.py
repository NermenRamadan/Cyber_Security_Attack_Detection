"""
scapy_capture_fixed.py — CyberShield live packet capture (FIXED)
بيبعت الـ 20 binary features + الـ 73 multi features للـ API

=====================================================================
الفروقات عن النسخة الأصلية (scapy_capture.py):

1. TCP Stream  -> بقى bidirectional (مش اتجاهي) + بيتعمله reset لو الستريم
   ساكت لفترة طويلة، عشان منوصلش لأرقام ضخمة غريبة عن التدريب.

2. deltatime   -> بقى per-connection (لكل stream/flow لوحده) مش عالمي على
   كل التراف��ك. ده أقرب لمنطق التدريب (كل CSV كان فيه نوع ترافيك واحد بس).

3. is_browser / is_attack_tool / is_script -> اتسابوا زي ما هما (الموديل
   مدرّب عليهم كده) لكن دلوقتي فيه تعليق واضح إنهم هيفضلوا صفر مع HTTPS،
   وده قيد حقيقي مش حاجة ممكن "نصلحها" من غير إعادة تدريب.
=====================================================================
"""
import time
import uuid
import requests
from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP, Raw

# ── Device ID ────────────────────────────────────────────────────
def get_device_id():
    import uuid as _u
    return str(_u.UUID(int=uuid.getnode()))

DEVICE_ID = get_device_id()
MY_USER_ID = ""   # ← حط الـ user_id بتاعك هنا

API_URL = "http://127.0.0.1:8000/predict/full"

# ── Feature lists (مطابقة للموديل) ──────────────────────────────
BINARY_FEATURES = [
    'deltatime', 'ip_flag_df', 'TCP Window Size', 'is_browser',
    'ip_flag_none', 'tcp_rst', 'is_attack_tool',
    'TCP Acknowledgment Number', 'is_http_1_0', 'has_dns_query',
    'TCP Sequence Number', 'TCP Destination Port', 'Length',
    'is_http_error', 'tcp_psh', 'TCP Stream', 'is_script',
    'is_http_response', 'TCP Source Port', 'HTTP Content-Length'
]

MULTI_FEATURES = [
    'TCP SYN Flag', 'TCP ACK Flag', 'TCP FIN Flag', 'TCP RST Flag',
    'TCP Window Size', 'TCP Stream', 'UDP Source Port', 'UDP Destination Port',
    'ICMP Type', 'deltatime', 'is_http_response', 'is_2xx', 'is_3xx', 'is_4xx',
    'is_5xx', 'is_http_success', 'is_http_request', 'is_suspicious_method',
    'is_attack_tool', 'is_browser', 'is_script', 'is_bot', 'uri_has_params',
    'is_sqli_path', 'is_system_file_attack', 'uri_path_depth', 'uri_length',
    'uri_has_special', 'has_sql', 'has_xss', 'has_path_traversal', 'has_admin',
    'is_http_1_0', 'has_dns_query', 'is_html', 'is_text', 'is_binary', 'is_image',
    'is_form', 'is_udp', 'is_icmp_echo', 'is_icmp_reply', 'is_icmp_unreachable',
    'is_icmp_packet', 'is_tcp_packet', 'tcp_stream_exists', 'tcp_seq_exists',
    'tcp_ack_exists', 'tcp_syn', 'tcp_ack', 'tcp_fin', 'tcp_rst', 'tcp_psh',
    'tcp_urg', 'has_ip_source', 'has_ip_dest', 'ip_flag_df', 'ip_flag_mf',
    'ip_flag_none', 'is_fragmented', 'is_zero_deltatime', 'pps', 'packet_rate',
    'icmp_rate', 'icmp_suspicious', 'is_fast_traffic', 'syn_ratio',
    'small_packet', 'medium_packet', 'large_packet', 'is_common_ttl',
    'ttl_anomaly', 'ttl_dev'
]

# ── State ────────────────────────────────────────────────────────
# [FIX 1+2] بدل last_time[0] العالمي وبدل tcp_stream_map الاتجاهي،
# بقى عندنا dict واحد لكل "flow" (اتصال) فيه: رقم الستريم + آخر وقت شوفنا
# فيه باكت من نفس الـ flow ده.
#
# flow_key = tuple bidirectional موحّد لاتجاهين الاتصال
flows = {}            # flow_key -> {"stream_id": int, "last_seen": float}
stream_id_counter = [0]

FLOW_TIMEOUT = 120.0   # ثانية - لو الـ flow ساكت أكتر من كده، نعتبره خلص ونرجّع رقمه للاستخدام

# لحساب الـ rate features (دول لسه عالميين بطبيعتهم - مقصودين كده)
packet_times = []
icmp_times   = []
syn_count    = [0]
total_count  = [0]
WINDOW       = 5.0   # ثواني للـ rate window

COMMON_TTLS  = {32, 64, 128, 255}


def get_flow_key(proto, ip_src, ip_dst, src_port, dst_port):
    """
    [FIX 1] مفتاح bidirectional: نرتب الطرفين عشان (A->B) و(B->A)
    ياخدوا نفس الـ flow_key بالظبط - زي tcp.stream في Wireshark فعليًا.
    """
    endpoint_a = (ip_src, src_port)
    endpoint_b = (ip_dst, dst_port)
    ordered = tuple(sorted([endpoint_a, endpoint_b]))
    return (proto, ordered[0], ordered[1])


def get_flow_state(flow_key, now):
    """
    [FIX 1+2] يرجع (stream_id, deltatime) للـ flow ده.
    - لو flow جديد: ياخد رقم جديد، وdeltatime = 0 (أول باكت في الاتصال).
    - لو flow قديم بس "منتهي" (ساكت أكتر من FLOW_TIMEOUT): نعتبره اتصال
      جديد فعليًا (زي ما بيحصل في الواقع لما TCP connection يتقفل ويتفتح تاني).
    - غير كده: deltatime = الفرق من آخر باكت في نفس الـ flow بس (مش كل
      الترافيك اللي بيمر على الكارت).
    """
    state = flows.get(flow_key)

    if state is None or (now - state["last_seen"]) > FLOW_TIMEOUT:
        stream_id_counter[0] += 1
        flows[flow_key] = {"stream_id": stream_id_counter[0], "last_seen": now}
        return flows[flow_key]["stream_id"], 0.0

    deltatime = now - state["last_seen"]
    state["last_seen"] = now
    return state["stream_id"], deltatime


def cleanup_old_flows(now):
    """تنظيف دوري بسيط عشان الـ dict ميكبرش لانهائي على جلسة طويلة."""
    if len(flows) < 5000:
        return
    dead = [k for k, v in flows.items() if (now - v["last_seen"]) > FLOW_TIMEOUT]
    for k in dead:
        del flows[k]


def extract_features(pkt):
    now = time.time()

    # ── Rate tracking (عالمي - ده مقصود، عشان نقيس الحمل الكلي على الكارت) ──
    packet_times.append(now)
    total_count[0] += 1

    cutoff = now - WINDOW
    while packet_times and packet_times[0] < cutoff:
        packet_times.pop(0)
    while icmp_times and icmp_times[0] < cutoff:
        icmp_times.pop(0)

    pps         = len(packet_times) / WINDOW
    packet_rate = pps
    icmp_rate   = len(icmp_times) / WINDOW

    length = len(pkt)

    # ── IP ────────────────────────────────────────────────────────
    has_ip_source = has_ip_dest = 0
    ip_flag_df = ip_flag_mf = ip_flag_none = 0
    is_fragmented = 0
    ttl = 0
    is_common_ttl = ttl_anomaly = 0
    ttl_dev = 0.0
    ip_src = ip_dst = None

    if IP in pkt:
        has_ip_source = 1
        has_ip_dest   = 1
        ip_src        = pkt[IP].src
        ip_dst        = pkt[IP].dst
        flags         = int(pkt[IP].flags)
        ip_flag_df    = 1 if flags & 0x02 else 0
        ip_flag_mf    = 1 if flags & 0x01 else 0
        ip_flag_none  = 1 if flags == 0 else 0
        is_fragmented = 1 if pkt[IP].frag > 0 else 0
        ttl           = pkt[IP].ttl
        is_common_ttl = 1 if ttl in COMMON_TTLS else 0
        ttl_anomaly   = 1 if ttl < 10 or ttl > 200 else 0
        diffs         = [abs(ttl - c) for c in COMMON_TTLS]
        ttl_dev       = float(min(diffs))

    # ── TCP ───────────────────────────────────────────────────────
    is_tcp_packet = tcp_window = tcp_rst = tcp_psh = tcp_urg = 0
    tcp_syn = tcp_ack = tcp_fin = 0
    tcp_seq = tcp_ack_num = tcp_dst_port = tcp_src_port = tcp_stream = 0
    tcp_seq_exists = tcp_ack_exists = tcp_stream_exists = 0
    tcp_syn_flag = tcp_ack_flag = tcp_fin_flag = tcp_rst_flag = 0

    flow_key = None

    if TCP in pkt:
        is_tcp_packet  = 1
        t              = pkt[TCP]
        tcp_flags      = int(t.flags)
        tcp_window     = int(t.window)
        tcp_syn        = 1 if tcp_flags & 0x02 else 0
        tcp_ack        = 1 if tcp_flags & 0x10 else 0
        tcp_fin        = 1 if tcp_flags & 0x01 else 0
        tcp_rst        = 1 if tcp_flags & 0x04 else 0
        tcp_psh        = 1 if tcp_flags & 0x08 else 0
        tcp_urg        = 1 if tcp_flags & 0x20 else 0
        tcp_syn_flag   = tcp_syn
        tcp_ack_flag   = tcp_ack
        tcp_fin_flag   = tcp_fin
        tcp_rst_flag   = tcp_rst
        tcp_seq        = int(t.seq)
        tcp_ack_num    = int(t.ack)
        tcp_dst_port   = int(t.dport)
        tcp_src_port   = int(t.sport)
        tcp_seq_exists = 1
        tcp_ack_exists = 1 if tcp_ack else 0

        if IP in pkt:
            flow_key = get_flow_key("TCP", ip_src, ip_dst, tcp_src_port, tcp_dst_port)
            tcp_stream_exists = 1

        if tcp_syn:
            syn_count[0] += 1

    # ── UDP ───────────────────────────────────────────────────────
    is_udp = udp_src_port = udp_dst_port = 0
    if UDP in pkt:
        is_udp        = 1
        udp_src_port  = int(pkt[UDP].sport)
        udp_dst_port  = int(pkt[UDP].dport)
        if IP in pkt and flow_key is None:
            flow_key = get_flow_key("UDP", ip_src, ip_dst, udp_src_port, udp_dst_port)

    # ── ICMP ──────────────────────────────────────────────────────
    is_icmp_packet = icmp_type_val = 0
    is_icmp_echo = is_icmp_reply = is_icmp_unreachable = icmp_suspicious = 0
    if ICMP in pkt:
        is_icmp_packet     = 1
        icmp_type_val      = int(pkt[ICMP].type)
        is_icmp_echo       = 1 if icmp_type_val == 8 else 0
        is_icmp_reply      = 1 if icmp_type_val == 0 else 0
        is_icmp_unreachable = 1 if icmp_type_val == 3 else 0
        icmp_suspicious    = 1 if icmp_rate > 50 else 0
        icmp_times.append(now)
        if IP in pkt and flow_key is None:
            flow_key = get_flow_key("ICMP", ip_src, ip_dst, 0, 0)

    # [FIX 1+2] لو في flow_key (TCP/UDP/ICMP فيها IP)، نجيب stream_id
    # و deltatime اللي بتاعه هو بس (مش الترافيك كله). غير كده fallback
    # لـ flow_key عام بناءً على الـ IPs بس.
    if flow_key is None and IP in pkt:
        flow_key = get_flow_key("IP", ip_src, ip_dst, 0, 0)

    if flow_key is not None:
        sid, deltatime = get_flow_state(flow_key, now)
        if is_tcp_packet:
            tcp_stream = sid
            tcp_stream_exists = 1
    else:
        # باكت من غير IP - حالة نادرة (ARP مثلاً)، منستخدمش deltatime عالمي تاني
        deltatime = 0.0

    cleanup_old_flows(now)

    # ── DNS ───────────────────────────────────────────────────────
    has_dns_query = 1 if DNS in pkt else 0

    # ── HTTP ──────────────────────────────────────────────────────
    # [ملاحظة مهمة] الفيتشرز دي (is_browser, is_attack_tool, is_script,
    # is_http_*) بتعتمد على إن الـ payload يكون نص HTTP واضح (plaintext).
    # مع HTTPS (اللي هو الغالبية العظمى من التراف��ك العادي النهاردة) الـ
    # payload بيكون مشفّر، فالفيتشرز دي هتفضل صفر حتى لو الترافيك طبيعي
    # 100%. ده قيد حقيقي في تصميم الموديل نفسه ومش حاجة ينصلح من كود
    # الالتقاط - الحل الجذري إنك تضيف traffic عادي HTTPS لداتاسيت
    # التدريب وتدّي الموديل فرصة يتعلم باترن "Normal" غير قائم على HTTP
    # plaintext بس.
    is_http_response = is_http_request = is_http_1_0 = 0
    is_http_success  = is_http_error   = is_http_redirect = 0
    is_2xx = is_3xx = is_4xx = is_5xx  = 0
    http_content_len = 0
    is_attack_tool = is_browser = is_script = is_bot = 0
    is_suspicious_method = 0
    uri_has_params = is_sqli_path = is_system_file_attack = 0
    uri_path_depth = uri_length = uri_has_special = 0
    has_sql = has_xss = has_path_traversal = has_admin = 0
    is_html = is_text = is_binary = is_image = is_form = 0

    if TCP in pkt and Raw in pkt:
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            pl_low  = payload.lower()

            if 'HTTP/1.0' in payload:
                is_http_1_0 = 1

            if payload.startswith('HTTP/'):
                is_http_response = 1
                parts = payload.split(' ')
                if len(parts) >= 2:
                    code = parts[1]
                    if code.startswith('2'):
                        is_2xx = is_http_success = 1
                    elif code.startswith('3'):
                        is_3xx = is_http_redirect = 1
                    elif code.startswith('4'):
                        is_4xx = is_http_error = 1
                    elif code.startswith('5'):
                        is_5xx = is_http_error = 1

            if any(payload.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']):
                is_http_request = 1
                method = payload.split(' ')[0]
                if method in ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']:
                    is_suspicious_method = 1

                try:
                    uri = payload.split(' ')[1]
                    uri_length     = len(uri)
                    uri_path_depth = uri.count('/')
                    uri_has_params = 1 if '?' in uri else 0
                    uri_has_special = 1 if any(c in uri for c in ['<', '>', '"', "'", ';', '(', ')']) else 0
                    uri_low = uri.lower()
                    is_sqli_path          = 1 if any(k in uri_low for k in ["'", 'union', 'select', 'drop', 'insert']) else 0
                    is_system_file_attack = 1 if any(k in uri_low for k in ['etc/passwd', 'win.ini', '../', '..\\']) else 0
                    has_path_traversal    = 1 if '../' in uri or '..\\' in uri else 0
                    has_admin             = 1 if 'admin' in uri_low else 0
                except Exception:
                    pass

            if 'Content-Type:' in payload:
                ct = payload.split('Content-Type:')[1].split('\r\n')[0].lower()
                is_html   = 1 if 'html' in ct else 0
                is_text   = 1 if 'text' in ct else 0
                is_binary = 1 if 'octet-stream' in ct else 0
                is_image  = 1 if 'image' in ct else 0
                is_form   = 1 if 'form' in ct else 0

            if 'Content-Length:' in payload:
                try:
                    cl = payload.split('Content-Length:')[1].split('\r\n')[0].strip()
                    http_content_len = int(cl)
                except Exception:
                    pass

            has_sql           = 1 if any(k in pl_low for k in ['select ', 'union ', 'drop ', 'insert ', 'delete from']) else 0
            has_xss           = 1 if any(k in pl_low for k in ['<script', 'javascript:', 'onerror=', 'onload=']) else 0
            is_attack_tool    = 1 if any(k in pl_low for k in ['sqlmap', 'nmap', 'nikto', 'hydra', 'metasploit', 'ffuf', 'masscan']) else 0
            is_browser        = 1 if any(k in pl_low for k in ['mozilla', 'chrome', 'firefox', 'safari', 'edge']) else 0
            is_script         = 1 if any(k in pl_low for k in ['python', 'curl', 'wget', 'requests', 'go-http']) else 0
            is_bot            = 1 if any(k in pl_low for k in ['bot', 'crawler', 'spider', 'scraper']) else 0

        except Exception:
            pass

    # ── Rate / traffic features ───────────────────────────────────
    syn_ratio      = syn_count[0] / max(total_count[0], 1)
    is_fast_traffic = 1 if pps > 100 else 0
    is_zero_deltatime = 1 if deltatime < 0.0001 else 0
    small_packet   = 1 if length < 64 else 0
    medium_packet  = 1 if 64 <= length <= 1500 else 0
    large_packet   = 1 if length > 1500 else 0

    # ── Build dicts ───────────────────────────────────────────────
    all_vals = {
        'deltatime': deltatime, 'ip_flag_df': ip_flag_df,
        'TCP Window Size': tcp_window, 'is_browser': is_browser,
        'ip_flag_none': ip_flag_none, 'tcp_rst': tcp_rst,
        'is_attack_tool': is_attack_tool,
        'TCP Acknowledgment Number': tcp_ack_num,
        'is_http_1_0': is_http_1_0, 'has_dns_query': has_dns_query,
        'TCP Sequence Number': tcp_seq,
        'TCP Destination Port': tcp_dst_port, 'Length': length,
        'is_http_error': is_http_error, 'tcp_psh': tcp_psh,
        'TCP Stream': tcp_stream, 'is_script': is_script,
        'is_http_response': is_http_response,
        'TCP Source Port': tcp_src_port,
        'HTTP Content-Length': http_content_len,
        # multi-only
        'TCP SYN Flag': tcp_syn_flag, 'TCP ACK Flag': tcp_ack_flag,
        'TCP FIN Flag': tcp_fin_flag, 'TCP RST Flag': tcp_rst_flag,
        'UDP Source Port': udp_src_port, 'UDP Destination Port': udp_dst_port,
        'ICMP Type': icmp_type_val,
        'is_2xx': is_2xx, 'is_3xx': is_3xx, 'is_4xx': is_4xx, 'is_5xx': is_5xx,
        'is_http_success': is_http_success, 'is_http_request': is_http_request,
        'is_suspicious_method': is_suspicious_method,
        'is_bot': is_bot, 'uri_has_params': uri_has_params,
        'is_sqli_path': is_sqli_path,
        'is_system_file_attack': is_system_file_attack,
        'uri_path_depth': uri_path_depth, 'uri_length': uri_length,
        'uri_has_special': uri_has_special,
        'has_sql': has_sql, 'has_xss': has_xss,
        'has_path_traversal': has_path_traversal, 'has_admin': has_admin,
        'is_html': is_html, 'is_text': is_text, 'is_binary': is_binary,
        'is_image': is_image, 'is_form': is_form,
        'is_udp': is_udp, 'is_icmp_echo': is_icmp_echo,
        'is_icmp_reply': is_icmp_reply,
        'is_icmp_unreachable': is_icmp_unreachable,
        'is_icmp_packet': is_icmp_packet, 'is_tcp_packet': is_tcp_packet,
        'tcp_stream_exists': tcp_stream_exists,
        'tcp_seq_exists': tcp_seq_exists, 'tcp_ack_exists': tcp_ack_exists,
        'tcp_syn': tcp_syn, 'tcp_ack': tcp_ack, 'tcp_fin': tcp_fin,
        'tcp_urg': tcp_urg,
        'has_ip_source': has_ip_source, 'has_ip_dest': has_ip_dest,
        'ip_flag_mf': ip_flag_mf, 'is_fragmented': is_fragmented,
        'is_zero_deltatime': is_zero_deltatime,
        'pps': pps, 'packet_rate': packet_rate, 'icmp_rate': icmp_rate,
        'icmp_suspicious': icmp_suspicious, 'is_fast_traffic': is_fast_traffic,
        'syn_ratio': syn_ratio,
        'small_packet': small_packet, 'medium_packet': medium_packet,
        'large_packet': large_packet,
        'is_common_ttl': is_common_ttl, 'ttl_anomaly': ttl_anomaly,
        'ttl_dev': ttl_dev,
    }

    binary_features = [all_vals.get(f, 0.0) for f in BINARY_FEATURES]
    multi_features  = {f: float(all_vals.get(f, 0.0)) for f in MULTI_FEATURES}

    return binary_features, multi_features


def process_packet(pkt):
    if IP not in pkt:
        return
    try:
        binary_features, multi_features = extract_features(pkt)

        response = requests.post(
            API_URL,
            json={
                "binary_features": binary_features,
                "multi_features":  multi_features,
                "user_id":         MY_USER_ID,
                "source_ip":       pkt[IP].src,
                "device_id":       DEVICE_ID,
                "protocol":        "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP",
            },
            timeout=5,
        )
        result = response.json()
        confidence = result.get("confidence")
        bin_conf   = result.get("binary_confidence")
        conf_str   = f"{confidence * 100:.1f}%" if confidence is not None else "N/A"
        bin_str    = f"{bin_conf * 100:.1f}%" if bin_conf is not None else "N/A"
        #result = response.json()
        #confidence = result.get("confidence")
        #conf_str   = f"{confidence * 100:.1f}%" if confidence is not None else "N/A"
        if result.get("is_attack"):
            print(f"🔴 ATTACK | {result['attack_type']:20s} | {result['severity']:8s} | multi={conf_str} | bin={bin_str} | {pkt[IP].src}")
        else:
            print(f"🟢 Normal |                      |          | bin={bin_str} | {pkt[IP].src}")
        #if result.get("is_attack"):
        #    print(f"🔴 ATTACK | {result['attack_type']:20s} | {result['severity']:8s} | {conf_str} | {pkt[IP].src}")
        #else:
        #    print(f"🟢 Normal |                      |          | {conf_str} | {pkt[IP].src}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("  CyberShield — Live Packet Capture (FIXED)")
    print("  Sending to:", API_URL)
    print("  Press Ctrl+C to stop")
    print("=" * 60)
    sniff(filter="ip", prn=process_packet, store=0)