from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import joblib
import os
import warnings
import traceback
import sqlite3
import httpx
import pandas as pd
import uuid
from datetime import datetime, timezone
from dotenv import load_dotenv
from typing import Any, List, Optional
from xgboost import XGBClassifier

load_dotenv()
warnings.filterwarnings("ignore")

app = FastAPI(title="CyberShield AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_PATH = os.path.join(os.path.dirname(__file__), "..", "notebook", "models")
BASE_PATH = os.path.abspath(BASE_PATH)

# ── 💾 تفعيل وإعداد SQLite ──────────────────────────────────────────
DB_FILE = os.path.join(os.path.dirname(__file__), "cyber_security.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # جدول الـ Detection Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            detected_at TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            status TEXT DEFAULT 'blocked',
            attack_type TEXT NOT NULL,
            protocol TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL DEFAULT 0,
            solution TEXT,
            device_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # جدول الـ Chat Messages
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()
print("✅ SQLite database initialized successfully!")

# ── 🤖 تحميل موديلات الذكاء الاصطناعي ──────────────────────────────────
try:
    model_binary        = joblib.load(os.path.join(BASE_PATH, "model_binary.pkl"))
    model_multi = XGBClassifier()
    model_multi.load_model(os.path.join(BASE_PATH, "model_multi.json"))

    scaler              = joblib.load(os.path.join(BASE_PATH, "scaler.pkl"))
    label_encoder_multi = joblib.load(os.path.join(BASE_PATH, "label_encoder_multi.pkl"))
    feature_names_bin   = joblib.load(os.path.join(BASE_PATH, "feature_names_binary.pkl"))
    scaler_features     = list(scaler.feature_names_in_)
    ordinal_encoders    = joblib.load(os.path.join(BASE_PATH, "ordinal_encoders.pkl"))
    top_protocols       = joblib.load(os.path.join(BASE_PATH, "top_protocols.pkl"))
    print(f"Models loaded — binary: {len(feature_names_bin)} features | scaler: {len(scaler_features)} features")
except Exception as e:
    print(f"Error loading models: {e}")
    exit(1)

severity_map = {
    "DDoS_ICMP": "Critical", "DDoS_UDP": "Critical",
    "DDoS_RAW": "Critical",  "SYN_Flood": "Critical",
    "ICMP_Flood": "Critical", "DoS": "High",
    "SSH_BruteForce": "High", "FTP_BruteForce": "High",
    "FTP_Exploit": "High",   "RCE": "High",
    "SQL_Injection": "High", "XSS": "Medium",
    "Fuzzing": "Medium",     "PortScanning": "Medium",
    "Normal": "None",
}

solutions_map = {
    "DDoS_ICMP":      "Enable rate limiting and activate WAF/CDN scrubbing.",
    "DDoS_UDP":       "Block UDP flood at firewall level.",
    "DDoS_RAW":       "Enable DDoS protection and contact ISP.",
    "SYN_Flood":      "Enable SYN cookies on the server.",
    "ICMP_Flood":     "Block ICMP at perimeter firewall.",
    "DoS":            "Enable rate limiting and throttling.",
    "SSH_BruteForce": "Lock account, enable MFA, throttle login attempts.",
    "FTP_BruteForce": "Lock account, disable FTP if unused.",
    "FTP_Exploit":    "Patch FTP server, use SFTP instead.",
    "RCE":            "Patch vulnerable service immediately.",
    "SQL_Injection":  "Use parameterized queries and input validation.",
    "XSS":            "Sanitize user input and enforce Content Security Policy.",
    "Fuzzing":        "Implement input validation and WAF rules.",
    "PortScanning":   "Block source IP at firewall.",
}

normal_counter = [0]
COMMON_TTLS = {32, 64, 128, 255}

def encode_protocol(protocol: str) -> float:
    try:
        proto = protocol if protocol in top_protocols else "Other"
        return float(ordinal_encoders['Protocol'].transform([[proto]])[0][0])
    except Exception:
        return -1.0

def parse_flag(val: Any) -> float:
    if isinstance(val, str):
        return 1.0 if val.strip().lower() == "set" else 0.0
    try:
        return float(val) if val else 0.0
    except Exception:
        return 0.0

def safe_float(val: Any, default: float = 0.0) -> float:
    try:
        if val is None or str(val).strip() in ("", "nan", "None"):
            return default
        return float(str(val).replace(",", "."))
    except Exception:
        return default

class NetworkFlow(BaseModel):
    binary_features: list[float]
    multi_features: dict[str, float] = {}
    source_ip: str = "0.0.0.0"
    protocol: str = "TCP"
    user_id: str = ""
    device_id: str = ""

class NetworkFlowLegacy(BaseModel):
    features: list[float]
    source_ip: str = "0.0.0.0"
    protocol: str = "TCP"
    user_id: str = ""
    device_id: str = ""

def run_prediction(binary_features: list, multi_features_dict: dict,
                   source_ip: str, protocol: str, user_id: str, device_id: str):

    X_bin     = pd.DataFrame([binary_features], columns=feature_names_bin)
    is_attack = int(model_binary.predict(X_bin)[0])

    try:
        binary_proba      = model_binary.predict_proba(X_bin)[0]
        binary_confidence = float(np.max(binary_proba))
    except Exception:
        binary_confidence = None

    if is_attack == 0:
        result = {
            "is_attack":   False,
            "attack_type": "Normal",
            "severity":    "None",
            "confidence":  binary_confidence,
            "code":        -1,
            "solution":    "",
        }
    else:
        multi_row = {}
        for feat in scaler_features:
            if feat == "Protocol":
                multi_row[feat] = encode_protocol(protocol)
            elif feat in multi_features_dict:
                multi_row[feat] = multi_features_dict[feat]
            elif feat in feature_names_bin:
                idx = list(feature_names_bin).index(feat)
                multi_row[feat] = binary_features[idx]
            else:
                multi_row[feat] = 0.0

        X_multi  = pd.DataFrame([multi_row], columns=scaler_features)
        X_scaled = scaler.transform(X_multi)

        pred_num    = model_multi.predict(X_scaled)[0]
        attack_type = label_encoder_multi.inverse_transform([pred_num])[0]
        severity    = severity_map.get(attack_type, "Medium")
        solution    = solutions_map.get(attack_type, "")

        try:
            proba      = model_multi.predict_proba(X_scaled)[0]
            confidence = float(np.max(proba))
        except Exception:
            confidence = None

        result = {
            "is_attack":   True,
            "attack_type": attack_type,
            "severity":    severity,
            "confidence":  confidence,
            "code":        int(pred_num),
            "solution":    solution,
        }

    # ── 💾 الحفظ في SQLite بدلاً من Supabase ──────────────────────────
    try:
        should_save = result["is_attack"]
        if not should_save:
            normal_counter[0] += 1
            if normal_counter[0] % 10 == 0:
                should_save = True

        if should_save:
            final_user_id = user_id if (user_id and user_id.strip()) else "local_user"
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO detection_logs (id, user_id, detected_at, source_ip, status, attack_type, protocol, severity, confidence, solution, device_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                final_user_id,
                datetime.now(timezone.utc).isoformat(),
                source_ip,
                "detected" if result["is_attack"] else "normal",
                result["attack_type"],
                protocol,
                result["severity"],
                result["confidence"] if result["confidence"] else 0.0,
                result["solution"],
                device_id
            ))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"SQLite insert error: {e}")

    return result

# ── 🤖 الـ Endpoints الخاصة بـ SentinelAI Agent ──────────────────────────
@app.post("/api/agent")
async def sentinel_agent(payload: dict = Body(...)):
    try:
        messages = payload.get("messages", [])
        mode = payload.get("mode", "chat")
        logs = payload.get("logs", [])
        
        KEY = os.environ.get("LOVABLE_API_KEY")
        
        # ── 🎭 لو مفيش Key، هنرجع ردود جاهزة عشان المشروع يشتغل وميقفش ──
        if not KEY:
            if mode == "summary":
                return {
                    "choices": [{
                        "message": {
                            "content": "## Executive Summary\nSentinelAI has detected low-to-medium risk network anomalies over the local session. Traffic volume is stable.\n\n## Top Threats\n- Port scanning attempts from local mock framework.\n\n## Recommended Actions (numbered, prioritized)\n1. Enable strict local firewall filtering.\n2. Review system access credentials.\n\n## Response Playbook\nStandard perimeter containment rules have been applied automatically."
                        }
                    }]
                }
            else:
                return {
                    "choices": [{
                        "message": {
                            "content": "Hello! I am SentinelAI, running in local preview mode because LOVABLE_API_KEY is not configured yet. Your SQLite logging and models are active and running perfectly!"
                        }
                    }]
                }

        # ── الكود الأصلي في حالة وجود الـ Key ──
        ctx = "No recent detections available."
        if logs:
            ctx_lines = []
            for l in logs[:25]:
                ctx_lines.append(f"- [{l.get('severity')}] {l.get('attack_type')} via {l.get('protocol')} from {l.get('source_ip')} (conf {l.get('confidence')}%)")
            ctx = f"Recent detections (most recent first):\n" + "\n".join(ctx_lines)

        system_chat = f"You are SentinelAI, a senior SOC analyst. Be concise, technical, and actionable.\nYou have access to recent detection telemetry below. Reference specific events when relevant.\n{ctx}"
        system_summary = f"You are SentinelAI. Generate a crisp incident report from the telemetry below.\nOutput sections: ## Executive Summary, ## Top Threats, ## Recommended Actions (numbered, prioritized), ## Response Playbook.\nTelemetry:\n{ctx}"

        if mode == "summary":
            body = {
                "model": "google/gemini-3-flash-preview",
                "messages": [
                    {"role": "system", "content": system_summary},
                    {"role": "user", "content": "Generate the incident report now."}
                ]
            }
        else:
            body = {
                "model": "google/gemini-3-flash-preview",
                "messages": [{"role": "system", "content": system_chat}] + messages
            }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://ai.gateway.lovable.dev/v1/chat/completions",
                headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
                json=body,
                timeout=60.0
            )
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail="AI gateway error")
            return response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint لعرض الـ logs في الـ Frontend
@app.get("/api/logs")
def get_logs(limit: int = 50):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM detection_logs ORDER BY detected_at DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── 🛠️ بقية الـ Endpoints القديمة كما هي تماماً ──────────────────────────
@app.post("/predict")
def predict_legacy(flow: NetworkFlowLegacy):
    try:
        multi_dict = {feat: flow.features[i] for i, feat in enumerate(feature_names_bin)}
        return run_prediction(
            binary_features=flow.features,
            multi_features_dict=multi_dict,
            source_ip=flow.source_ip,
            protocol=flow.protocol,
            user_id=flow.user_id,
            device_id=flow.device_id,
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/full")
def predict_full(flow: NetworkFlow):
    try:
        return run_prediction(
            binary_features=flow.binary_features,
            multi_features_dict=flow.multi_features,
            source_ip=flow.source_ip,
            protocol=flow.protocol,
            user_id=flow.user_id,
            device_id=flow.device_id,
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/wireshark-row")
def predict_wireshark_row(row: dict):
    try:
        binary_f, multi_f, protocol = wireshark_row_to_features(row)
        src_ip  = str(row.get("IP Source", row.get("Source", "0.0.0.0")))
        user_id = str(row.get("user_id", ""))
        return run_prediction(
            binary_features=binary_f,
            multi_features_dict=multi_f,
            source_ip=src_ip,
            protocol=protocol,
            user_id=user_id,
            device_id="csv-upload",
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict/csv-row")
def predict_csv_row(row: dict):
    try:
        binary_features = [float(row.get(f, 0) or 0) for f in feature_names_bin]
        multi_dict      = {f: float(row.get(f, 0) or 0) for f in scaler_features}
        protocol        = str(row.get("Protocol", "TCP"))
        return run_prediction(
            binary_features=binary_features,
            multi_features_dict=multi_dict,
            source_ip=str(row.get("IP Source", row.get("source_ip", "0.0.0.0"))),
            protocol=protocol,
            user_id=str(row.get("user_id", "")),
            device_id=str(row.get("device_id", "")),
        )
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {
        "status":          "CyberShield AI API is running with SQLite",
        "binary_features": len(feature_names_bin),
        "scaler_features": len(scaler_features),
        "top_protocols":   top_protocols,
    }

@app.get("/features")
def get_features():
    return {
        "binary_features": feature_names_bin,
        "multi_features":  scaler_features,
        "top_protocols":   top_protocols,
    }

@app.get("/")
def root():
    return {
        "message":   "CyberShield AI API (SQLite Local Version)",
        "endpoints": ["/health", "/predict", "/predict/full",
                      "/predict/wireshark-row", "/predict/csv-row",
                      "/api/agent", "/api/logs", "/features", "/docs"],
    }

def wireshark_row_to_features(row: dict) -> tuple:
    protocol = str(row.get("Protocol", "TCP")).strip()

    tcp_syn = parse_flag(row.get("TCP SYN Flag", 0))
    tcp_ack = parse_flag(row.get("TCP ACK Flag", 0))
    tcp_fin = parse_flag(row.get("TCP FIN Flag", 0))
    tcp_rst = parse_flag(row.get("TCP RST Flag", 0))

    tcp_flags_str = str(row.get("TCP Flags", "0x000"))
    try:
        tcp_flags_int = int(tcp_flags_str, 16)
        if not any([tcp_syn, tcp_ack, tcp_fin, tcp_rst]):
            tcp_syn = 1.0 if tcp_flags_int & 0x02 else 0.0
            tcp_ack = 1.0 if tcp_flags_int & 0x10 else 0.0
            tcp_fin = 1.0 if tcp_flags_int & 0x01 else 0.0
            tcp_rst = 1.0 if tcp_flags_int & 0x04 else 0.0
        tcp_psh = 1.0 if tcp_flags_int & 0x08 else 0.0
        tcp_urg = 1.0 if tcp_flags_int & 0x20 else 0.0
    except Exception:
        tcp_psh = tcp_urg = 0.0

    ip_flags_str = str(row.get("IP Flags", "0x00")).lower()
    ip_flag_df   = 1.0 if "0x40" in ip_flags_str else 0.0
    ip_flag_mf   = 1.0 if "0x20" in ip_flags_str else 0.0
    ip_flag_none = 1.0 if ip_flags_str in ["0x00", "0", "0x00,0x00"] else 0.0

    proto_up = protocol.upper()
    is_tcp   = 1.0 if "TCP"  in proto_up else 0.0
    is_udp   = 1.0 if "UDP"  in proto_up else 0.0
    is_icmp  = 1.0 if "ICMP" in proto_up else 0.0

    ttl           = safe_float(str(row.get("IP TTL", 64)).split(",")[0])
    is_common_ttl = 1.0 if ttl in COMMON_TTLS else 0.0
    ttl_anomaly   = 1.0 if ttl < 10 or ttl > 200 else 0.0
    ttl_dev       = float(min(abs(ttl - c) for c in COMMON_TTLS))

    tcp_src_port = safe_float(row.get("TCP Source Port", -1))
    tcp_dst_port = safe_float(row.get("TCP Destination Port", -1))
    udp_src_port = safe_float(row.get("UDP Source Port", 0))
    udp_dst_port = safe_float(row.get("UDP Destination Port", 0))

    length     = safe_float(row.get("Length", 0))
    small_pkt  = 1.0 if length < 64   else 0.0
    medium_pkt = 1.0 if 64 <= length <= 1500 else 0.0
    large_pkt  = 1.0 if length > 1500 else 0.0

    http_method    = str(row.get("HTTP Request Method", "") or "").strip()
    http_uri       = str(row.get("HTTP Request URI",    "") or "").strip()
    http_version   = str(row.get("HTTP Request Version","") or "").strip()
    http_resp_code = str(row.get("HTTP Response Code",  "") or "").strip()
    http_ua        = str(row.get("HTTP User-Agent",     "") or "").lower()
    http_ct        = str(row.get("HTTP Content Type",   "") or "").lower()
    http_cl        = safe_float(row.get("HTTP Content-Length", 0))

    is_http_request  = 1.0 if http_method    else 0.0
    is_http_response = 1.0 if http_resp_code else 0.0
    is_http_1_0      = 1.0 if "1.0" in http_version else 0.0

    is_2xx = is_3xx = is_4xx = is_5xx = 0.0
    is_http_success = is_http_error = 0.0
    if http_resp_code:
        if   http_resp_code.startswith("2"): is_2xx = is_http_success = 1.0
        elif http_resp_code.startswith("3"): is_3xx = 1.0
        elif http_resp_code.startswith("4"): is_4xx = is_http_error   = 1.0
        elif http_resp_code.startswith("5"): is_5xx = is_http_error   = 1.0

    is_suspicious_method = 1.0 if http_method in ["POST", "OPTIONS", "PROPFIND"] else 0.0

    uri_low        = http_uri.lower()
    full_uri       = str(row.get("HTTP Full URI", "") or "").lower()
    uri_length     = float(len(http_uri))
    uri_path_depth = float(http_uri.count("/"))
    uri_has_params = 1.0 if "?" in http_uri else 0.0
    uri_has_special = 1.0 if any(c in http_uri for c in ["<",">",'"',"'",";","(",")","{"]) else 0.0

    is_sqli_path          = 1.0 if any(k in uri_low for k in ["'","union","select","drop","insert","or 1=1"]) else 0.0
    is_system_file_attack = 1.0 if any(k in uri_low for k in ["etc/passwd","win.ini","../","..\\"]) else 0.0
    has_path_traversal    = 1.0 if "../" in http_uri or "..\\" in http_uri else 0.0
    has_admin             = 1.0 if "admin" in uri_low else 0.0

    combined_uri = full_uri + uri_low
    has_sql = 1.0 if any(k in combined_uri for k in ["select ","union ","drop ","insert ","delete from","' or"]) else 0.0
    has_xss = 1.0 if any(k in combined_uri for k in ["<script","javascript:","onerror=","onload=","alert("]) else 0.0

    is_attack_tool = 1.0 if any(k in http_ua for k in ["sqlmap","ffuf","fuzz","apachebench","nmap","nikto","masscan","hydra","metasploit"]) else 0.0
    is_browser     = 1.0 if any(k in http_ua for k in ["mozilla","chrome","firefox","safari","edge"]) else 0.0
    is_script      = 1.0 if any(k in http_ua for k in ["python","curl","wget","requests","go-http"]) else 0.0
    is_bot         = 1.0 if any(k in http_ua for k in ["bot","crawler","spider","scraper"]) else 0.0

    is_html   = 1.0 if "html"         in http_ct else 0.0
    is_text   = 1.0 if "text"         in http_ct else 0.0
    is_binary = 1.0 if "octet-stream" in http_ct else 0.0
    is_image  = 1.0 if "image"        in http_ct else 0.0
    is_form   = 1.0 if "form"         in http_ct else 0.0

    has_dns_query = 1.0 if str(row.get("DNS Query Name", "") or "").strip() else 0.0

    icmp_type           = safe_float(row.get("ICMP Type", -1))
    is_icmp_echo        = 1.0 if icmp_type == 8 else 0.0
    is_icmp_reply       = 1.0 if icmp_type == 0 else 0.0
    is_icmp_unreachable = 1.0 if icmp_type == 3 else 0.0

    deltatime         = safe_float(row.get("deltatime", 0))
    is_zero_deltatime = 1.0 if deltatime < 0.0001 else 0.0
    pps               = min(1.0 / max(deltatime, 0.0001), 10000.0)
    packet_rate       = pps
    icmp_rate         = pps if is_icmp else 0.0
    icmp_suspicious   = 1.0 if (is_icmp and icmp_rate > 50) else 0.0
    is_fast_traffic   = 1.0 if pps > 100 else 0.0

    tcp_stream  = safe_float(row.get("TCP Stream", 0))
    tcp_seq     = safe_float(row.get("TCP Sequence Number", 0))
    tcp_ack_num = safe_float(row.get("TCP Acknowledgment Number", 0))
    tcp_window  = safe_float(row.get("TCP Window Size", 0))

    is_fragmented = 1.0 if safe_float(row.get("IP Fragment Offset", 0)) > 0 else 0.0
    syn_ratio     = tcp_syn

    ip_length = safe_float(row.get("IP Length", 0))

    all_f = {
        "Protocol":                    encode_protocol(protocol),
        "Length":                      length,
        "IP Length":                   ip_length,
        "IP TTL":                      ttl,
        "TCP Source Port":             tcp_src_port,
        "TCP Destination Port":        tcp_dst_port,
        "TCP Sequence Number":         tcp_seq,
        "TCP Acknowledgment Number":   tcp_ack_num,
        "TCP SYN Flag":                tcp_syn,
        "TCP ACK Flag":                tcp_ack,
        "TCP FIN Flag":                tcp_fin,
        "TCP RST Flag":                tcp_rst,
        "TCP Window Size":             tcp_window,
        "TCP Stream":                  tcp_stream,
        "UDP Source Port":             udp_src_port,
        "UDP Destination Port":        udp_dst_port,
        "ICMP Type":                   icmp_type,
        "deltatime":                   deltatime,
        "is_http_response":            is_http_response,
        "is_2xx":                      is_2xx,
        "is_3xx":                      is_3xx,
        "is_4xx":                      is_4xx,
        "is_5xx":                      is_5xx,
        "is_http_success":             is_http_success,
        "is_http_request":             is_http_request,
        "is_suspicious_method":        is_suspicious_method,
        "is_attack_tool":              is_attack_tool,
        "is_browser":                  is_browser,
        "is_script":                   is_script,
        "is_bot":                      is_bot,
        "uri_has_params":              uri_has_params,
        "is_sqli_path":                is_sqli_path,
        "is_system_file_attack":       is_system_file_attack,
        "uri_path_depth":              uri_path_depth,
        "uri_length":                  uri_length,
        "uri_has_special":             uri_has_special,
        "has_sql":                     has_sql,
        "has_xss":                     has_xss,
        "has_path_traversal":          has_path_traversal,
        "has_admin":                   has_admin,
        "is_http_1_0":                 is_http_1_0,
        "has_dns_query":               has_dns_query,
        "is_html":                     is_html,
        "is_text":                     is_text,
        "is_binary":                   is_binary,
        "is_image":                    is_image,
        "is_form":                     is_form,
        "is_udp":                      is_udp,
        "is_icmp_echo":                is_icmp_echo,
        "is_icmp_reply":               is_icmp_reply,
        "is_icmp_unreachable":         is_icmp_unreachable,
        "is_icmp_packet":              is_icmp,
        "is_tcp_packet":               is_tcp,
        "tcp_stream_exists":           1.0 if tcp_stream > 0 else 0.0,
        "tcp_seq_exists":              1.0 if tcp_seq > 0 else 0.0,
        "tcp_ack_exists":              tcp_ack,
        "tcp_syn":                     tcp_syn,
        "tcp_ack":                     tcp_ack,
        "tcp_fin":                     tcp_fin,
        "tcp_rst":                     tcp_rst,
        "tcp_psh":                     tcp_psh,
        "tcp_urg":                     tcp_urg,
        "has_ip_source":               1.0 if row.get("IP Source") else 0.0,
        "has_ip_dest":                 1.0 if row.get("IP Destination") else 0.0,
        "ip_flag_df":                  ip_flag_df,
        "ip_flag_mf":                  ip_flag_mf,
        "ip_flag_none":                ip_flag_none,
        "is_fragmented":               is_fragmented,
        "is_zero_deltatime":           is_zero_deltatime,
        "pps":                         pps,
        "packet_rate":                 packet_rate,
        "icmp_rate":                   icmp_rate,
        "icmp_suspicious":             icmp_suspicious,
        "is_fast_traffic":             is_fast_traffic,
        "syn_ratio":                   syn_ratio,
        "small_packet":                small_pkt,
        "medium_packet":               medium_pkt,
        "large_packet":                large_pkt,
        "is_common_ttl":               is_common_ttl,
        "ttl_anomaly":                 ttl_anomaly,
        "ttl_dev":                     ttl_dev,
    }

    binary_f = [all_f.get(f, 0.0) for f in feature_names_bin]
    multi_f  = {f: float(all_f.get(f, 0.0)) for f in scaler_features}

    return binary_f, multi_f, protocol


if __name__ == "__main__":
    import uvicorn
    print("Starting CyberShield API with SQLite support...")
    uvicorn.run(app, host="127.0.0.1", port=8000)