"""
wireshark_test_capture.py — اختبار تشخيصي
========================================
بيستخدم tshark (مش Scapy) عشان يستخرج فيتشرز حقيقية مطابقة لطريقة
تدريب الموديل بالظبط (TCP Stream الحقيقي من Wireshark، Frame Time الحقيقي،
إلخ)، ويبعتها لـ /predict/wireshark-row.

الهدف: نفصل المشكلة. لو النتيجة لسه غلط (XSS على تصفح عادي) رغم إننا
بنستخدم بيانات Wireshark حقيقية 100% -> المشكلة في الموديل نفسه (leakage).
لو النتيجة بقت صح -> المشكلة كانت في طريقة استخراج الفيتشرز بـ Scapy.

التشغيل: شغّله كـ Administrator (لازم صلاحيات عشان الـ live capture يشتغل
على Windows مع Npcap).
"""
import os
import time
import requests
import pyshark

# ── مسار tshark.exe (عدّله لو مختلف عندك) ────────────────────────
TSHARK_PATH = r"D:\Wireshark\tshark.exe"

# ── إعدادات ──────────────────────────────────────────────────────
API_URL          = "http://127.0.0.1:8000/predict/wireshark-row"
INTERFACE        = "WiFi"      # ← اسم الكارت بالظبط كما ظهر من tshark -D
CAPTURE_SECONDS  = 120          # دقيقتين تصفح عادي


def build_row(pkt, deltatime: float) -> dict:
    """يبني dict بنفس أسامي الأعمدة اللي الـ API بتاع wireshark_row_to_features متوقعها."""
    row = {"deltatime": deltatime, "Length": int(pkt.length)}

    # أقرب حاجة لعمود "Protocol" في واجهة Wireshark
    row["Protocol"] = getattr(pkt, "highest_layer", "TCP")

    if hasattr(pkt, "ip"):
        ip = pkt.ip
        row["IP Source"]          = getattr(ip, "src", "")
        row["IP Destination"]     = getattr(ip, "dst", "")
        row["IP TTL"]             = getattr(ip, "ttl", 64)
        row["IP Flags"]           = getattr(ip, "flags", "0x00")
        row["IP Fragment Offset"] = getattr(ip, "frag_offset", 0)
        row["IP Length"]          = getattr(ip, "len", 0)

    if hasattr(pkt, "tcp"):
        t = pkt.tcp
        row["TCP Source Port"]           = getattr(t, "srcport", 0)
        row["TCP Destination Port"]      = getattr(t, "dstport", 0)
        row["TCP Sequence Number"]       = getattr(t, "seq", 0)
        row["TCP Acknowledgment Number"] = getattr(t, "ack", 0)
        row["TCP Window Size"]           = getattr(t, "window_size", 0)
        # ده tcp.stream الحقيقي من Wireshark - bidirectional وموثوق فيه 100%
        row["TCP Stream"]                = getattr(t, "stream", 0)
        row["TCP Flags"]                 = getattr(t, "flags", "0x000")
        row["TCP SYN Flag"]              = getattr(t, "flags_syn", "0")
        row["TCP ACK Flag"]              = getattr(t, "flags_ack", "0")
        row["TCP FIN Flag"]              = getattr(t, "flags_fin", "0")
        row["TCP RST Flag"]              = getattr(t, "flags_reset", "0")

    if hasattr(pkt, "udp"):
        row["UDP Source Port"]      = getattr(pkt.udp, "srcport", 0)
        row["UDP Destination Port"] = getattr(pkt.udp, "dstport", 0)

    if hasattr(pkt, "icmp"):
        row["ICMP Type"] = getattr(pkt.icmp, "type", -1)

    if hasattr(pkt, "http"):
        h = pkt.http
        row["HTTP Request Method"]  = getattr(h, "request_method", "")
        row["HTTP Request URI"]     = getattr(h, "request_uri", "")
        row["HTTP Request Version"] = getattr(h, "request_version", "")
        row["HTTP Response Code"]   = getattr(h, "response_code", "")
        row["HTTP User-Agent"]      = getattr(h, "user_agent", "")
        row["HTTP Content Type"]    = getattr(h, "content_type", "")
        row["HTTP Content-Length"]  = getattr(h, "content_length", 0)
        row["HTTP Full URI"]        = getattr(h, "request_full_uri", "")

    if hasattr(pkt, "dns"):
        row["DNS Query Name"] = getattr(pkt.dns, "qry_name", "")

    return row


def main():
    print("=" * 60)
    print("  Wireshark-based diagnostic test")
    print(f"  Interface: {INTERFACE} | Duration: {CAPTURE_SECONDS}s")
    print(f"  Sending to: {API_URL}")
    print("=" * 60)

    cap = pyshark.LiveCapture(interface=INTERFACE, tshark_path=TSHARK_PATH)

    last_time = None
    count = 0
    attack_count = 0
    start = time.time()

    try:
        for pkt in cap.sniff_continuously():
            if time.time() - start > CAPTURE_SECONDS:
                break
            if not hasattr(pkt, "ip"):
                continue

            try:
                now = float(pkt.sniff_timestamp)
                deltatime = 0.0 if last_time is None else max(now - last_time, 0.0)
                last_time = now

                row = build_row(pkt, deltatime)
                row["user_id"] = ""

                resp = requests.post(API_URL, json=row, timeout=5)
                result = resp.json()
                count += 1

                ip_src = row.get("IP Source", "?")
                conf       = result.get("confidence") or 0
                bin_conf   = result.get("binary_confidence") or 0

                if result.get("is_attack"):
                    attack_count += 1
                    print(f"🔴 ATTACK | {result['attack_type']:15s} | {result['severity']:8s} | "
                          f"multi={conf*100:.1f}% | bin={bin_conf*100:.1f}% | {ip_src}")
                else:
                    print(f"🟢 Normal | bin={bin_conf*100:.1f}% | {ip_src}")

            except Exception as e:
                print(f"⚠️  Error on packet: {e}")

    except KeyboardInterrupt:
        pass
    finally:
        cap.close()

    print("\n" + "=" * 60)
    print(f"  Done. {count} packets sent | {attack_count} flagged as attack "
          f"({(attack_count/count*100) if count else 0:.1f}%)")
    print("=" * 60)


if __name__ == "__main__":
    main()