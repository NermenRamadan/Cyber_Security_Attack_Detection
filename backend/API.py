from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import joblib
import os
import warnings
import traceback
from supabase import create_client
import pandas as pd
from datetime import datetime, timezone
from dotenv import load_dotenv
from typing import Any

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

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

try:
    sb = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_KEY else None
    print("Supabase connected" if sb else "WARNING: Supabase not connected")
except Exception as e:
    print(f"Supabase error: {e}")
    sb = None

try:
    model_binary        = joblib.load(os.path.join(BASE_PATH, "model_binary.pkl"))
    model_multi         = joblib.load(os.path.join(BASE_PATH, "model_multi.pkl"))
    scaler              = joblib.load(os.path.join(BASE_PATH, "scaler.pkl"))
    label_encoder_multi = joblib.load(os.path.join(BASE_PATH, "label_encoder_multi.pkl"))
    feature_names_bin   = joblib.load(os.path.join(BASE_PATH, "feature_names_binary.pkl"))
    scaler_features     = list(scaler.feature_names_in_)
    ordinal_encoders    = joblib.load(os.path.join(BASE_PATH, "ordinal_encoders.pkl"))
    label_encoder_proto = joblib.load(os.path.join(BASE_PATH, "label_encoder_protocol.pkl"))
    top_protocols       = joblib.load(os.path.join(BASE_PATH, "top_protocols.pkl"))
    print(f"Models loaded — binary: {len(feature_names_bin)} features | scaler: {len(scaler_features)} features")
    print(f"Top protocols: {top_protocols}")
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
        encoded = float(ordinal_encoders['Protocol'].transform([[proto]])[0][0])
        return encoded
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
                idx = feature_names_bin.index(feat)
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
            confidence = float(np.max(model_multi.predict_proba(X_scaled)[0]))
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

    if sb:
        try:
            should_save = False
            if result["is_attack"]:
                should_save = True
            else:
                normal_counter[0] += 1
                if normal_counter[0] % 10 == 0:
                    should_save = True

            if should_save:
                final_user_id = user_id if (user_id and user_id.strip()) else None
                sb.table("detection_logs").insert({
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "source_ip":   source_ip,
                    "status":      "detected" if result["is_attack"] else "normal",
                    "attack_type": result["attack_type"],
                    "protocol":    protocol,
                    "severity":    result["severity"],
                    "confidence":  result["confidence"],
                    "solution":    result["solution"],
                    "user_id":     final_user_id,
                    "device_id":   device_id,
                }).execute()
        except Exception as e:
            print(f"Supabase insert error: {e}")

    return result


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
        "status":           "CyberShield API is running",
        "supabase":         "connected" if sb else "disconnected",
        "binary_features":  len(feature_names_bin),
        "scaler_features":  len(scaler_features),
        "top_protocols":    top_protocols,
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
        "message":   "CyberShield AI API",
        "endpoints": ["/health", "/predict", "/predict/full",
                      "/predict/wireshark-row", "/predict/csv-row",
                      "/features", "/docs"],
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
    except Exception:
        tcp_psh = 0.0

    ip_flags_str = str(row.get("IP Flags", "0x00"))
    try:
        ip_flags_int = int(ip_flags_str, 16)
        ip_flag_df   = 1.0 if ip_flags_int & 0x02 else 0.0
        ip_flag_mf   = 1.0 if ip_flags_int & 0x01 else 0.0
        ip_flag_none = 1.0 if ip_flags_int == 0 else 0.0
    except Exception:
        ip_flag_df = ip_flag_mf = ip_flag_none = 0.0

    proto_up  = protocol.upper()
    is_tcp    = 1.0 if "TCP" in proto_up else 0.0
    is_udp    = 1.0 if "UDP" in proto_up else 0.0
    is_icmp   = 1.0 if "ICMP" in proto_up else 0.0

    ttl = safe_float(row.get("IP TTL", 64))
    is_common_ttl = 1.0 if ttl in COMMON_TTLS else 0.0
    ttl_anomaly   = 1.0 if ttl < 10 or ttl > 200 else 0.0
    ttl_dev       = float(min(abs(ttl - c) for c in COMMON_TTLS))

    tcp_src_port = safe_float(row.get("TCP Source Port", 0))
    tcp_dst_port = safe_float(row.get("TCP Destination Port", 0))
    udp_src_port = safe_float(row.get("UDP Source Port", 0))
    udp_dst_port = safe_float(row.get("UDP Destination Port", 0))

    length     = safe_float(row.get("Length", row.get("frame length", 0)))
    small_pkt  = 1.0 if length < 64 else 0.0
    medium_pkt = 1.0 if 64 <= length <= 1500 else 0.0
    large_pkt  = 1.0 if length > 1500 else 0.0

    http_method    = str(row.get("HTTP Request Method", "")).strip()
    http_uri       = str(row.get("HTTP Request URI", "")).strip()
    http_version   = str(row.get("HTTP Request Version", "")).strip()
    http_resp_code = str(row.get("HTTP Response Code", "")).strip()
    http_ua        = str(row.get("HTTP User-Agent", "")).lower()
    http_ct        = str(row.get("HTTP Content Type", "")).lower()
    http_cl        = safe_float(row.get("HTTP Content-Length", 0))

    is_http_request  = 1.0 if http_method else 0.0
    is_http_response = 1.0 if http_resp_code else 0.0
    is_http_1_0      = 1.0 if "1.0" in http_version else 0.0

    is_2xx = is_3xx = is_4xx = is_5xx = 0.0
    is_http_success = is_http_error = 0.0
    if http_resp_code:
        if http_resp_code.startswith("2"): is_2xx = is_http_success = 1.0
        elif http_resp_code.startswith("3"): is_3xx = 1.0
        elif http_resp_code.startswith("4"): is_4xx = is_http_error = 1.0
        elif http_resp_code.startswith("5"): is_5xx = is_http_error = 1.0

    is_suspicious_method = 1.0 if http_method in ["PUT","DELETE","PATCH","OPTIONS","TRACE"] else 0.0

    uri_low        = http_uri.lower()
    uri_length     = float(len(http_uri))
    uri_path_depth = float(http_uri.count("/"))
    uri_has_params = 1.0 if "?" in http_uri else 0.0
    uri_has_special = 1.0 if any(c in http_uri for c in ["<",">",'"',"'",";","(",")","{"]) else 0.0
    is_sqli_path   = 1.0 if any(k in uri_low for k in ["'","union","select","drop","insert","or 1=1"]) else 0.0
    is_system_file_attack = 1.0 if any(k in uri_low for k in ["etc/passwd","win.ini","../","..\\"]) else 0.0
    has_path_traversal = 1.0 if "../" in http_uri or "..\\" in http_uri else 0.0
    has_admin = 1.0 if "admin" in uri_low else 0.0

    full_uri = str(row.get("HTTP Full URI", "")).lower()
    has_sql = 1.0 if any(k in full_uri + uri_low for k in ["select ","union ","drop ","insert ","delete from","' or"]) else 0.0
    has_xss = 1.0 if any(k in full_uri + uri_low for k in ["<script","javascript:","onerror=","onload=","alert("]) else 0.0

    is_attack_tool = 1.0 if any(k in http_ua for k in ["sqlmap","nmap","nikto","hydra","metasploit","ffuf","masscan","apachebench"]) else 0.0
    is_browser = 1.0 if any(k in http_ua for k in ["mozilla","chrome","firefox","safari","edge"]) else 0.0
    is_script = 1.0 if any(k in http_ua for k in ["python","curl","wget","requests","go-http"]) else 0.0
    is_bot = 1.0 if any(k in http_ua for k in ["bot","crawler","spider","scraper"]) else 0.0

    is_html = 1.0 if "html" in http_ct else 0.0
    is_text = 1.0 if "text" in http_ct else 0.0
    is_binary = 1.0 if "octet-stream" in http_ct else 0.0
    is_image = 1.0 if "image" in http_ct else 0.0
    is_form = 1.0 if "form" in http_ct else 0.0

    has_dns_query = 1.0 if str(row.get("DNS Query Name","")).strip() else 0.0

    icmp_type = safe_float(row.get("ICMP Type", 0))
    is_icmp_echo = 1.0 if icmp_type == 8 else 0.0
    is_icmp_reply = 1.0 if icmp_type == 0 else 0.0
    is_icmp_unreachable = 1.0 if icmp_type == 3 else 0.0

    deltatime = safe_float(row.get("deltatime", 0))
    is_zero_deltatime = 1.0 if deltatime < 0.0001 else 0.0

    tcp_stream = safe_float(row.get("TCP Stream", 0))
    tcp_seq = safe_float(row.get("TCP Sequence Number", 0))
    tcp_ack_num = safe_float(row.get("TCP Acknowledgment Number", 0))
    tcp_window = safe_float(row.get("TCP Window Size", 0))
    is_fragmented = 1.0 if safe_float(row.get("IP Fragment Offset", 0)) > 0 else 0.0

    pps = min(1.0 / max(deltatime, 0.0001), 10000.0)
    packet_rate = pps
    icmp_rate = pps if is_icmp else 0.0
    icmp_suspicious = 1.0 if (is_icmp and icmp_rate > 50) else 0.0
    is_fast_traffic = 1.0 if pps > 100 else 0.0
    syn_ratio = tcp_syn

    all_f = {
        "deltatime": deltatime,
        "ip_flag_df": ip_flag_df,
        "TCP Window Size": tcp_window,
        "is_browser": is_browser,
        "ip_flag_none": ip_flag_none,
        "tcp_rst": tcp_rst,
        "is_attack_tool": is_attack_tool,

        "TCP Sequence Number": tcp_seq,
        "Length": length,
        "Protocol": encode_protocol(protocol),
        "TCP Source Port": tcp_src_port,
        "TCP Acknowledgment Number": tcp_ack_num,
        "TCP Destination Port": tcp_dst_port,
        "IP TTL": safe_float(row.get("IP TTL", 64)),
        "IP Length": safe_float(row.get("IP Length", 0)),

        "is_http_1_0": is_http_1_0,
        "has_dns_query": has_dns_query,
        "TCP Stream": tcp_stream,
        "is_http_error": is_http_error,
        "tcp_psh": tcp_psh,
        "is_script": is_script,
        "is_http_response": is_http_response,
        "HTTP Content-Length": http_cl,
        "TCP SYN Flag": tcp_syn,
        "TCP ACK Flag": tcp_ack,
        "TCP FIN Flag": tcp_fin,
        "TCP RST Flag": tcp_rst,
        "UDP Source Port": udp_src_port,
        "UDP Destination Port": udp_dst_port,
        "ICMP Type": icmp_type,
        "is_2xx": is_2xx,
        "is_3xx": is_3xx,
        "is_4xx": is_4xx,
        "is_5xx": is_5xx,
        "is_http_success": is_http_success,
        "is_http_request": is_http_request,
        "is_suspicious_method": is_suspicious_method,
        "is_bot": is_bot,
        "uri_has_params": uri_has_params,
        "is_sqli_path": is_sqli_path,
        "is_system_file_attack": is_system_file_attack,
        "uri_path_depth": uri_path_depth,
        "uri_length": uri_length,
        "uri_has_special": uri_has_special,
        "has_sql": has_sql,
        "has_xss": has_xss,
        "has_path_traversal": has_path_traversal,
        "has_admin": has_admin,
        "is_html": is_html,
        "is_text": is_text,
        "is_binary": is_binary,
        "is_image": is_image,
        "is_form": is_form,
        "is_udp": is_udp,
        "is_icmp_echo": is_icmp_echo,
        "is_icmp_reply": is_icmp_reply,
        "is_icmp_unreachable": is_icmp_unreachable,
        "is_icmp_packet": is_icmp,
        "is_tcp_packet": is_tcp,
        "tcp_stream_exists": 1.0 if tcp_stream > 0 else 0.0,
        "tcp_seq_exists": 1.0 if tcp_seq > 0 else 0.0,
        "tcp_ack_exists": tcp_ack,
        "tcp_syn": tcp_syn,
        "tcp_ack": tcp_ack,
        "tcp_fin": tcp_fin,
        "tcp_urg": 0.0,
        "has_ip_source": 1.0 if row.get("IP Source") else 0.0,
        "has_ip_dest": 1.0 if row.get("IP Destination") else 0.0,
        "ip_flag_mf": ip_flag_mf,
        "is_fragmented": is_fragmented,
        "is_zero_deltatime": is_zero_deltatime,
        "pps": pps,
        "packet_rate": packet_rate,
        "icmp_rate": icmp_rate,
        "icmp_suspicious": icmp_suspicious,
        "is_fast_traffic": is_fast_traffic,
        "syn_ratio": syn_ratio,
        "small_packet": small_pkt,
        "medium_packet": medium_pkt,
        "large_packet": large_pkt,
        "is_common_ttl": is_common_ttl,
        "ttl_anomaly": ttl_anomaly,
        "ttl_dev": ttl_dev,
    }

    binary_f = [all_f.get(f, 0.0) for f in feature_names_bin]
    multi_f  = {f: float(all_f.get(f, 0.0)) for f in scaler_features}

    return binary_f, multi_f, protocol


if __name__ == "__main__":
    import uvicorn
    print("Starting CyberShield API...")
    uvicorn.run(app, host="127.0.0.1", port=8000)