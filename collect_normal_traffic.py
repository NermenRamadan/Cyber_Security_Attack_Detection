"""
collect_normal_traffic.py — جمع بيانات Normal حقيقية للتدريب
=============================================================
السكريبت ده مش بيكلم الموديل ولا الـ API خالص — مفيهوش أي prediction.
هو بس بيستخرج نفس الفيتشرز الخام اللي الموديل اتدرب عليها (بنفس أسامي
الأعمدة بالظبط زي merged_dataset.csv)، ويحفظها في ملف CSV، مع عمودين
إضافيين بنحطهم إحنا يدويًا: label='Normal' و is_attack=0.

الهدف: نجمع traffic حقيقي (مش من نفس بيئة الـ dataset الأصلي) عشان
ندمجه بعدين مع merged_dataset.csv ونعيد التدريب، فيبقى عند الموديل
أمثلة حقيقية عن شكل الـ "Normal" الواقعي مش بس من بيئة معزولة.

الاستخدام:
1. شغّليه كـ Administrator لمدة 5-10 دقايق واتصفحي بتنوع (مواقع مختلفة،
   يوتيوب، تحميل ملف صغير، فتح تطبيقات).
2. هيحفظلك ملف CSV في نفس المجلد.
3. راجعي الملف بعينك قبل الدمج (اتأكدي إن مفيش سطر فاضي/غريب).
4. ادمجيه مع merged_dataset.csv (pd.concat) قبل التدريب.
"""
import time
import csv
import pyshark

# ── إعدادات ──────────────────────────────────────────────────────
TSHARK_PATH      = r"D:\Wireshark\tshark.exe"  
INTERFACE        = "WiFi"                        
CAPTURE_SECONDS  = 900                           
OUTPUT_CSV       = "normal_traffic_collected.csv"

# ── Flow tracking لحساب deltatime لكل flow لوحده ──────────────────
flows = {}
FLOW_TIMEOUT = 120.0


def get_flow_key(pkt) -> tuple:
    if not hasattr(pkt, "ip"):
        return ("no-ip",)

    proto = "OTHER"
    src_port = dst_port = 0
    if hasattr(pkt, "tcp"):
        proto = "TCP"
        src_port = getattr(pkt.tcp, "srcport", 0)
        dst_port = getattr(pkt.tcp, "dstport", 0)
    elif hasattr(pkt, "udp"):
        proto = "UDP"
        src_port = getattr(pkt.udp, "srcport", 0)
        dst_port = getattr(pkt.udp, "dstport", 0)
    elif hasattr(pkt, "icmp"):
        proto = "ICMP"

    ip = pkt.ip
    endpoint_a = (getattr(ip, "src", ""), src_port)
    endpoint_b = (getattr(ip, "dst", ""), dst_port)
    ordered = tuple(sorted([endpoint_a, endpoint_b]))
    return (proto, ordered[0], ordered[1])


def get_flow_deltatime(pkt, now: float) -> float:
    key = get_flow_key(pkt)
    last_seen = flows.get(key)

    if last_seen is None or (now - last_seen) > FLOW_TIMEOUT:
        flows[key] = now
        return 0.0

    deltatime = now - last_seen
    flows[key] = now
    return deltatime


def build_row(pkt, deltatime: float) -> dict:
    """نفس أعمدة merged_dataset.csv بالظبط — بدون أي تنبؤ أو استدعاء موديل."""
    row = {
        "deltatime": deltatime,
        "Length": int(pkt.length),
        "Protocol": getattr(pkt, "highest_layer", "TCP"),
        # ✅ FIX: لازم نسجل الوقت الحقيقي بنفس اسم العمود اللي نوتبوك v8 بيدور
        # عليه (Frame Time (Epoch)) — من غيرها، خطوة dropna(subset=[time_col])
        # في خلية حساب conn_count_10s/rst_ratio_10s كانت بتمسح كل صفوف الملف
        # ده بالكامل (لأنها معندهاش عمود وقت خالص)، فبيانات الـ Normal الحقيقية
        # دي كانت بتتشال من التدريب من غير ما حد يلاحظ.
        "Frame Time (Epoch)": float(pkt.sniff_timestamp),
    }

    if hasattr(pkt, "ip"):
        ip = pkt.ip
        row["IP Source"]          = getattr(ip, "src", "")
        row["IP Destination"]     = getattr(ip, "dst", "")
        row["IP TTL"]             = getattr(ip, "ttl", 64)
        row["IP Flags"]           = getattr(ip, "flags", "0x00")
        row["IP Fragment Offset"] = getattr(ip, "frag_offset", 0)
        row["IP Length"]          = getattr(ip, "len", 0)
        row["IP Version"]         = getattr(ip, "version", 4)

    if hasattr(pkt, "tcp"):
        t = pkt.tcp
        row["TCP Source Port"]           = getattr(t, "srcport", 0)
        row["TCP Destination Port"]      = getattr(t, "dstport", 0)
        row["TCP Sequence Number"]       = getattr(t, "seq", 0)
        row["TCP Acknowledgment Number"] = getattr(t, "ack", 0)
        row["TCP Window Size"]           = getattr(t, "window_size", 0)
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

    # ── العمودين المهمين اللي بنحطهم يدويًا ──────────────────────
    row["label"]     = "Normal"
    row["is_attack"] = 0

    return row


def main():
    print("=" * 60)
    print("  Collecting REAL Normal traffic (no model/API involved)")
    print(f"  Interface: {INTERFACE} | Duration: {CAPTURE_SECONDS}s")
    print(f"  Output: {OUTPUT_CSV}")
    print("=" * 60)
    print("اتصفحي عادي دلوقتي (مواقع مختلفة، يوتيوب، تحميل ملف...)")
    print()

    cap = pyshark.LiveCapture(interface=INTERFACE, tshark_path=TSHARK_PATH)

    rows = []
    start = time.time()
    count = 0

    try:
        for pkt in cap.sniff_continuously():
            if time.time() - start > CAPTURE_SECONDS:
                break
            if not hasattr(pkt, "ip"):
                continue

            try:
                now = float(pkt.sniff_timestamp)
                deltatime = get_flow_deltatime(pkt, now)
                row = build_row(pkt, deltatime)
                rows.append(row)
                count += 1

                if count % 100 == 0:
                    elapsed = int(time.time() - start)
                    remaining = CAPTURE_SECONDS - elapsed
                    print(f"  {count} packets collected | {elapsed}s elapsed | {remaining}s remaining")

            except Exception as e:
                print(f"⚠️  Error on packet (skipped): {e}")

    except KeyboardInterrupt:
        print("\n  Stopped early by user.")
    finally:
        cap.close()

    if not rows:
        print("\n⚠️  No packets collected. تأكدي من اسم الكارت (INTERFACE) وإنك بتصفحي فعليًا.")
        return

    # ── حفظ CSV — بنجمع كل الأعمدة اللي ظهرت في أي صف (بعض الصفوف
    # ممكن ماتحتويش على كل الأعمدة، زي صف UDP مفيهوش أعمدة TCP) ──
    all_fields = []
    seen = set()
    for row in rows:
        for k in row.keys():
            if k not in seen:
                seen.add(k)
                all_fields.append(k)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_fields)
        writer.writeheader()
        writer.writerows(rows)

    print("\n" + "=" * 60)
    print(f"  Done! {count} rows saved to: {OUTPUT_CSV}")
    print(f"  All rows labeled: label='Normal', is_attack=0")
    print("=" * 60)
    print("""
    import pandas as pd
    df_original = pd.read_csv('merged_dataset.csv', low_memory=False)
    df_normal_new = pd.read_csv('normal_traffic_collected.csv', low_memory=False)
    df_combined = pd.concat([df_original, df_normal_new], ignore_index=True)
    df_combined.to_csv('merged_dataset_v2.csv', index=False)
    """)


if __name__ == "__main__":
    main()