import pandas as pd
import numpy as np

# 1. تحميل الملف الجديد (المعدل من طرفك والذي يحتوي على Frame Time)
df = pd.read_csv('normal_traffic_collected.csv', low_memory=False)

# 2. بناء DataFrame جديد متوافق تماماً في الأسماء والفيتشرز
df_fixed = pd.DataFrame()

# المحافظة على عمود الوقت الحرج (مهم جداً لخطوة dropna في النوت بوك)
if 'Frame Time (Epoch)' in df.columns:
    df_fixed['Frame Time (Epoch)'] = df['Frame Time (Epoch)']
elif 'sniff_timestamp' in df.columns:
    df_fixed['Frame Time (Epoch)'] = df['sniff_timestamp']
else:
    df_fixed['Frame Time (Epoch)'] = pd.Timestamp.now().timestamp()

# نقل وبناء الفيتشرز الأساسية بالأسماء المتوقعة في الـ Dataset القديمة
df_fixed['Protocol'] = df['Protocol']
df_fixed['Length'] = df['Length']
df_fixed['IP TTL'] = df['IP TTL'].fillna(0)
df_fixed['TCP Source Port'] = df['TCP Source Port'].fillna(0)
df_fixed['TCP Destination Port'] = df['TCP Destination Port'].fillna(0)
df_fixed['TCP Window Size'] = df['TCP Window Size'].fillna(0)
df_fixed['UDP Source Port'] = df['UDP Source Port'].fillna(0)
df_fixed['UDP Destination Port'] = df['UDP Destination Port'].fillna(0)
df_fixed['ICMP Type'] = df['ICMP Type'].fillna(-1)
df_fixed['HTTP Content-Length'] = df['HTTP Content-Length'].fillna(0)
df_fixed['deltatime'] = df['deltatime'].fillna(0)

# تحويل أعلام الـ TCP إلى قيم رقمية (0 أو 1) مع معالجة الـ NaN
for flag in ['SYN', 'ACK', 'FIN', 'RST']:
    raw_col = f'TCP {flag} Flag'
    target_col = f'TCP {flag} Flag'
    if raw_col in df.columns:
        df_fixed[target_col] = df[raw_col].astype(str).str.lower().map({'true': 1, '1': 1, 'false': 0, '0': 0}).fillna(0)
    else:
        df_fixed[target_col] = 0

# إنشاء الفيتشرز المشتقة (الحتمية للموديل الكامل قبل مرحلة الاختزال لـ 25)
df_fixed['is_tcp_packet'] = df['Protocol'].astype(str).str.upper().str.contains('TCP').astype(int)
df_fixed['is_udp'] = df['Protocol'].astype(str).str.upper().str.contains('UDP|QUIC').astype(int)
df_fixed['is_icmp_packet'] = df['Protocol'].astype(str).str.upper().str.contains('ICMP').astype(int)

df_fixed['tcp_syn'] = df_fixed['TCP SYN Flag']
df_fixed['tcp_ack'] = df_fixed['TCP ACK Flag']
df_fixed['tcp_fin'] = df_fixed['TCP FIN Flag']
df_fixed['tcp_rst'] = df_fixed['TCP RST Flag']

# حل مشكلة الـ TypeError للـ Flags: نملأ الـ NaN بنصوص فارغة ونحول العمود بالكامل لنصوص يقيناً
tcp_flags_str = df['TCP Flags'].fillna('').astype(str)
df_fixed['tcp_psh'] = tcp_flags_str.apply(lambda x: 1 if '0x018' in x or '0x010' in x else 0)
df_fixed['tcp_urg'] = 0

# ── إصلاح فيتشرز الـ HTTP (آمن تماماً من الـ NaN والـ TypeError) ──────────────────
df_fixed['is_http_request'] = df['HTTP Request Method'].notna().astype(int)
df_fixed['is_http_response'] = df['HTTP Response Code'].notna().astype(int)

# نضمن تحويل العمود بالكامل لنصوص وملء أي NaN بنص فاضي ""
uri_str = df['HTTP Request URI'].fillna('').astype(str)

df_fixed['uri_has_params'] = uri_str.str.contains(r'\?').astype(int)
df_fixed['uri_length'] = uri_str.apply(lambda x: len(x) if x != 'nan' and x != '' else 0)
df_fixed['uri_path_depth'] = uri_str.apply(lambda x: x.count('/') if x != 'nan' and x != '' else 0)

# تصفير بقية أعمدة الهجوم لأن الحركة طبيعية ومجمعة يدوياً (Normal)
security_cols = [
    'is_sqli_path', 'is_system_file_attack', 'uri_has_special', 'has_admin', 
    'has_sql', 'has_xss', 'has_path_traversal', 'is_suspicious_method', 
    'is_http_success', 'is_http_error', 'is_attack_tool', 'is_browser', 
    'is_script', 'is_http_1_0', 'has_dns_query', 'tcp_stream_exists', 
    'tcp_seq_exists', 'tcp_ack_exists', 'has_ip_source', 'has_ip_dest', 
    'ip_flag_df', 'ip_flag_mf', 'ip_flag_none', 'has_ttl', 'conn_count_10s', 'rst_ratio_10s'
]
for col in security_cols:
    df_fixed[col] = 0

# تعيين قيم الـ Target الأساسية للداتا المجمعة
df_fixed['label'] = 'Normal'
df_fixed['is_attack'] = 0

# 3. حفظ الملف الجديد المصحح والمطابق تماماً
df_fixed.to_csv('normal_traffic_collected_fixed.csv', index=False)
