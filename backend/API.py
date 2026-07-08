from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Any, List, Optional, Literal
from datetime import datetime, timezone
from enum import Enum
import numpy as np
import joblib
import os
import warnings
import traceback
import sqlite3
import httpx
import pandas as pd
import uuid
from dotenv import load_dotenv
from xgboost import XGBClassifier

load_dotenv()
warnings.filterwarnings("ignore")

# ═══════════════════════════════════════════════════════════════════════════════
# APP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="CyberShield AI API",
    description="AI-powered cybersecurity attack detection and response platform",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "notebook", "models"))
DB_FILE = os.path.join(os.path.dirname(__file__), "cyber_security.db")


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"

class AttackType(str, Enum):
    DDOS_ICMP = "DDoS_ICMP"
    DDOS_UDP = "DDoS_UDP"
    DDOS_RAW = "DDoS_RAW"
    SYN_FLOOD = "SYN_Flood"
    ICMP_FLOOD = "ICMP_Flood"
    DOS = "DoS"
    SSH_BRUTEFORCE = "SSH_BruteForce"
    FTP_BRUTEFORCE = "FTP_BruteForce"
    FTP_EXPLOIT = "FTP_Exploit"
    RCE = "RCE"
    SQL_INJECTION = "SQL_Injection"
    XSS = "XSS"
    FUZZING = "Fuzzing"
    PORT_SCANNING = "PortScanning"
    NORMAL = "Normal"

severity_map = {
    AttackType.DDOS_ICMP: Severity.CRITICAL,
    AttackType.DDOS_UDP: Severity.CRITICAL,
    AttackType.DDOS_RAW: Severity.CRITICAL,
    AttackType.SYN_FLOOD: Severity.CRITICAL,
    AttackType.ICMP_FLOOD: Severity.CRITICAL,
    AttackType.DOS: Severity.HIGH,
    AttackType.SSH_BRUTEFORCE: Severity.HIGH,
    AttackType.FTP_BRUTEFORCE: Severity.HIGH,
    AttackType.FTP_EXPLOIT: Severity.HIGH,
    AttackType.RCE: Severity.HIGH,
    AttackType.SQL_INJECTION: Severity.HIGH,
    AttackType.XSS: Severity.MEDIUM,
    AttackType.FUZZING: Severity.MEDIUM,
    AttackType.PORT_SCANNING: Severity.MEDIUM,
    AttackType.NORMAL: Severity.NONE,
}

solutions_map = {
    AttackType.DDOS_ICMP: "Enable rate limiting and activate WAF/CDN scrubbing.",
    AttackType.DDOS_UDP: "Block UDP flood at firewall level.",
    AttackType.DDOS_RAW: "Enable DDoS protection and contact ISP.",
    AttackType.SYN_FLOOD: "Enable SYN cookies on the server.",
    AttackType.ICMP_FLOOD: "Block ICMP at perimeter firewall.",
    AttackType.DOS: "Enable rate limiting and throttling.",
    AttackType.SSH_BRUTEFORCE: "Lock account, enable MFA, throttle login attempts.",
    AttackType.FTP_BRUTEFORCE: "Lock account, disable FTP if unused.",
    AttackType.FTP_EXPLOIT: "Patch FTP server, use SFTP instead.",
    AttackType.RCE: "Patch vulnerable service immediately.",
    AttackType.SQL_INJECTION: "Use parameterized queries and input validation.",
    AttackType.XSS: "Sanitize user input and enforce Content Security Policy.",
    AttackType.FUZZING: "Implement input validation and WAF rules.",
    AttackType.PORT_SCANNING: "Block source IP at firewall.",
}

normal_counter = [0]
COMMON_TTLS = {32, 64, 128, 255}


# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS — REQUESTS
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkFlow(BaseModel):
    """Full prediction request with separate binary and multi-class features."""
    binary_features: List[float] = Field(..., description="Features for binary attack detection model")
    multi_features: dict[str, float] = Field(default_factory=dict, description="Additional features for multi-class classification")
    source_ip: str = Field(default="0.0.0.0", description="Source IP address")
    protocol: str = Field(default="TCP", description="Network protocol (TCP, UDP, ICMP)")
    user_id: str = Field(default="", description="User identifier")
    device_id: str = Field(default="", description="Device identifier")


class NetworkFlowLegacy(BaseModel):
    """Legacy prediction request using a single flat features list."""
    features: List[float] = Field(..., description="Flat feature vector for binary model")
    source_ip: str = Field(default="0.0.0.0", description="Source IP address")
    protocol: str = Field(default="TCP", description="Network protocol")
    user_id: str = Field(default="", description="User identifier")
    device_id: str = Field(default="", description="Device identifier")


class WiresharkRow(BaseModel):
    """Single Wireshark-exported row for prediction.

    Note: Wireshark columns with spaces (e.g. 'IP Source') are mapped via
    model_config populate_by_name. Send them as regular JSON keys.
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    Protocol: Optional[str] = Field(default="TCP")
    IP_Source: Optional[str] = Field(default="0.0.0.0", alias="IP Source")
    IP_Destination: Optional[str] = Field(default=None, alias="IP Destination")
    IP_TTL: Optional[Any] = Field(default=64, alias="IP TTL")
    IP_Length: Optional[Any] = Field(default=0, alias="IP Length")
    IP_Flags: Optional[str] = Field(default="0x00", alias="IP Flags")
    IP_Fragment_Offset: Optional[Any] = Field(default=0, alias="IP Fragment Offset")
    TCP_Source_Port: Optional[Any] = Field(default=-1, alias="TCP Source Port")
    TCP_Destination_Port: Optional[Any] = Field(default=-1, alias="TCP Destination Port")
    TCP_Sequence_Number: Optional[Any] = Field(default=0, alias="TCP Sequence Number")
    TCP_Acknowledgment_Number: Optional[Any] = Field(default=0, alias="TCP Acknowledgment Number")
    TCP_Window_Size: Optional[Any] = Field(default=0, alias="TCP Window Size")
    TCP_Stream: Optional[Any] = Field(default=0, alias="TCP Stream")
    TCP_SYN_Flag: Optional[Any] = Field(default=0, alias="TCP SYN Flag")
    TCP_ACK_Flag: Optional[Any] = Field(default=0, alias="TCP ACK Flag")
    TCP_FIN_Flag: Optional[Any] = Field(default=0, alias="TCP FIN Flag")
    TCP_RST_Flag: Optional[Any] = Field(default=0, alias="TCP RST Flag")
    TCP_Flags: Optional[str] = Field(default="0x000", alias="TCP Flags")
    UDP_Source_Port: Optional[Any] = Field(default=0, alias="UDP Source Port")
    UDP_Destination_Port: Optional[Any] = Field(default=0, alias="UDP Destination Port")
    ICMP_Type: Optional[Any] = Field(default=-1, alias="ICMP Type")
    Length: Optional[Any] = Field(default=0)
    deltatime: Optional[Any] = Field(default=0)
    DNS_Query_Name: Optional[str] = Field(default="", alias="DNS Query Name")
    HTTP_Request_Method: Optional[str] = Field(default="", alias="HTTP Request Method")
    HTTP_Request_URI: Optional[str] = Field(default="", alias="HTTP Request URI")
    HTTP_Full_URI: Optional[str] = Field(default="", alias="HTTP Full URI")
    HTTP_Request_Version: Optional[str] = Field(default="", alias="HTTP Request Version")
    HTTP_Response_Code: Optional[str] = Field(default="", alias="HTTP Response Code")
    HTTP_User_Agent: Optional[str] = Field(default="", alias="HTTP User-Agent")
    HTTP_Content_Type: Optional[str] = Field(default="", alias="HTTP Content Type")
    HTTP_Content_Length: Optional[Any] = Field(default=0, alias="HTTP Content-Length")
    user_id: Optional[str] = Field(default="")


class CSVRow(BaseModel):
    """Single CSV row for prediction — accepts any column names dynamically."""
    model_config = ConfigDict(extra="allow")

    Protocol: Optional[str] = Field(default="TCP")
    IP_Source: Optional[str] = Field(default=None, alias="IP Source")
    source_ip: Optional[str] = Field(default=None)
    user_id: Optional[str] = Field(default="")
    device_id: Optional[str] = Field(default="")


class ChatMessageRequest(BaseModel):
    """Request to save or send a chat message."""
    user_id: str = Field(default="local_user", description="User identifier")
    role: Literal["user", "assistant", "system"] = Field(..., description="Message role")
    content: str = Field(..., min_length=1, max_length=10000, description="Message content")
    session_id: Optional[str] = Field(default=None, description="Chat session identifier")

    @field_validator("content")
    @classmethod
    def content_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Content cannot be empty or whitespace only")
        return v.strip()


class AgentRequest(BaseModel):
    """Request to the AI Security Assistant (SentinelAI)."""
    messages: List[dict] = Field(default_factory=list, description="Chat history in OpenAI format")
    mode: Literal["chat", "summary"] = Field(default="chat", description="Agent mode")
    logs: List[dict] = Field(default_factory=list, description="Recent detection logs for context")
    user_id: Optional[str] = Field(default="local_user", description="User identifier")
    session_id: Optional[str] = Field(default=None, description="Chat session identifier")


# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS — RESPONSES
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionFeatures(BaseModel):
    """Network features extracted from the detection — matches Frontend expectations."""
    protocol: str = Field(default="N/A", description="Detected network protocol")
    dest_port: Optional[int] = Field(default=None, description="Destination port")
    source_ip: str = Field(default="0.0.0.0", description="Source IP address")
    source_port: Optional[int] = Field(default=None, description="Source port")
    length: Optional[float] = Field(default=None, description="Packet length")
    ttl: Optional[float] = Field(default=None, description="IP TTL value")


class PredictionResult(BaseModel):
    """Structured prediction result returned to the Frontend."""
    is_attack: bool = Field(..., description="Whether an attack was detected")
    attack_type: str = Field(..., description="Type of attack or 'Normal'")
    severity: str = Field(..., description="Severity level (Critical/High/Medium/Low/None)")
    confidence: Optional[float] = Field(default=None, ge=0, le=100, description="Multi-class confidence (0-100%)")
    binary_confidence: Optional[float] = Field(default=None, ge=0, le=100, description="Binary detection confidence (0-100%)")
    code: int = Field(..., description="Numeric attack class code (-1 for Normal)")
    solution: str = Field(default="", description="Recommended remediation action")
    features: DetectionFeatures = Field(default_factory=DetectionFeatures, description="Extracted network features")


class ChatMessageResponse(BaseModel):
    """Single chat message in the response format."""
    id: str = Field(..., description="Message unique identifier")
    user_id: str = Field(..., description="User identifier")
    role: str = Field(..., description="Message role")
    content: str = Field(..., description="Message content")
    created_at: str = Field(..., description="ISO 8601 timestamp")
    session_id: Optional[str] = Field(default=None, description="Session identifier")


class AgentResponse(BaseModel):
    """AI Assistant response — clean format for Frontend."""
    message: str = Field(..., description="AI-generated response text")
    role: str = Field(default="assistant", description="Message role")
    mode: str = Field(..., description="Response mode (chat/summary)")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    session_id: Optional[str] = Field(default=None, description="Session identifier")


class DetectionLog(BaseModel):
    """Single detection log entry."""
    id: str = Field(..., description="Log unique identifier")
    user_id: Optional[str] = Field(default=None)
    detected_at: str = Field(..., description="Detection timestamp")
    source_ip: str = Field(...)
    status: str = Field(..., description="Detection status")
    attack_type: str = Field(...)
    protocol: str = Field(...)
    severity: str = Field(...)
    confidence: float = Field(default=0.0)
    solution: Optional[str] = Field(default=None)
    device_id: Optional[str] = Field(default=None)
    created_at: str = Field(...)


class StatsOverview(BaseModel):
    """Dashboard statistics overview."""
    total_detections: int = Field(..., description="Total number of detections")
    total_attacks: int = Field(..., description="Total confirmed attacks")
    total_normal: int = Field(..., description="Total normal traffic records")
    severity_breakdown: dict[str, int] = Field(..., description="Count per severity level")
    attack_type_breakdown: dict[str, int] = Field(..., description="Count per attack type")
    last_detection_at: Optional[str] = Field(default=None, description="Most recent detection timestamp")


class TimelinePoint(BaseModel):
    """Single point in the detection timeline."""
    date: str = Field(..., description="Date string (YYYY-MM-DD)")
    count: int = Field(..., description="Number of detections on this date")
    attacks: int = Field(..., description="Number of attacks on this date")


# ═══════════════════════════════════════════════════════════════════════════════
# UNIFIED API RESPONSE WRAPPER
# ═══════════════════════════════════════════════════════════════════════════════

class ApiResponse(BaseModel):
    """Unified API response wrapper used by ALL endpoints."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    success: bool = Field(default=True, description="Whether the request succeeded")
    data: Optional[Any] = Field(default=None, description="Response payload")
    message: Optional[str] = Field(default=None, description="Human-readable status message")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Response timestamp")

    @classmethod
    def ok(cls, data: Any = None, message: str = "Success") -> "ApiResponse":
        return cls(success=True, data=data, message=message)

    @classmethod
    def error(cls, message: str = "An error occurred", data: Any = None) -> "ApiResponse":
        return cls(success=False, data=data, message=message)


class HealthStatus(BaseModel):
    """Health check response data."""
    status: str = Field(..., description="API status")
    version: str = Field(..., description="API version")
    binary_features: int = Field(..., description="Number of binary model features")
    scaler_features: int = Field(..., description="Number of scaler features")
    top_protocols: List[str] = Field(..., description="Supported protocols")
    database: str = Field(..., description="Database connection status")
    models_loaded: bool = Field(..., description="Whether ML models are loaded")


class FeaturesInfo(BaseModel):
    """Model features information."""
    binary_features: List[str] = Field(...)
    multi_features: List[str] = Field(...)
    top_protocols: List[str] = Field(...)


class ApiInfo(BaseModel):
    """Root endpoint information."""
    message: str = Field(...)
    version: str = Field(...)
    endpoints: List[str] = Field(...)
    documentation: str = Field(...)


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def init_db() -> None:
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            session_id TEXT,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Add session_id column if it doesnt exist (migration for existing DBs)
    try:
        cursor.execute("SELECT session_id FROM chat_messages LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE chat_messages ADD COLUMN session_id TEXT")

    conn.commit()
    conn.close()

init_db()
print("✅ SQLite database initialized successfully!")


# ═══════════════════════════════════════════════════════════════════════════════
# ML MODELS LOADING
# ═══════════════════════════════════════════════════════════════════════════════

try:
    model_binary = joblib.load(os.path.join(BASE_PATH, "model_binary.pkl"))
    model_multi = XGBClassifier()
    model_multi.load_model(os.path.join(BASE_PATH, "model_multi.json"))
    scaler = joblib.load(os.path.join(BASE_PATH, "scaler.pkl"))
    label_encoder_multi = joblib.load(os.path.join(BASE_PATH, "label_encoder_multi.pkl"))
    feature_names_bin = joblib.load(os.path.join(BASE_PATH, "feature_names_binary.pkl"))
    scaler_features = list(scaler.feature_names_in_)
    ordinal_encoders = joblib.load(os.path.join(BASE_PATH, "ordinal_encoders.pkl"))
    top_protocols = joblib.load(os.path.join(BASE_PATH, "top_protocols.pkl"))

    MODELS_LOADED = True
    print(f"Models loaded — binary: {len(feature_names_bin)} features | scaler: {len(scaler_features)} features")
except Exception as e:
    MODELS_LOADED = False
    print(f"❌ Error loading models: {e}")
    traceback.print_exc()


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def encode_protocol(protocol: str) -> float:
    """Encode protocol string to numeric value using ordinal encoder."""
    try:
        proto = protocol if protocol in top_protocols else "Other"
        return float(ordinal_encoders['Protocol'].transform([[proto]])[0][0])
    except Exception:
        return -1.0


def parse_flag(val: Any) -> float:
    """Parse a flag value to 0.0 or 1.0."""
    if isinstance(val, str):
        return 1.0 if val.strip().lower() == "set" else 0.0
    try:
        return float(val) if val else 0.0
    except Exception:
        return 0.0


def safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert a value to float with fallback."""
    try:
        if val is None or str(val).strip() in ("", "nan", "None"):
            return default
        return float(str(val).replace(",", "."))
    except Exception:
        return default


def build_detection_features(
    protocol: str,
    source_ip: str,
    tcp_dst_port: float = -1,
    tcp_src_port: float = -1,
    udp_dst_port: float = 0,
    udp_src_port: float = 0,
    length: float = 0,
    ttl: float = 64,
) -> DetectionFeatures:
    """Build DetectionFeatures from parsed network data."""
    dest_port = None
    source_port = None

    if tcp_dst_port > 0:
        dest_port = int(tcp_dst_port)
    elif udp_dst_port > 0:
        dest_port = int(udp_dst_port)

    if tcp_src_port > 0:
        source_port = int(tcp_src_port)
    elif udp_src_port > 0:
        source_port = int(udp_src_port)

    return DetectionFeatures(
        protocol=protocol.upper() if protocol else "N/A",
        dest_port=dest_port,
        source_ip=source_ip,
        source_port=source_port,
        length=length if length > 0 else None,
        ttl=ttl if ttl > 0 else None,
    )


def save_chat_message(user_id: str, role: str, content: str, session_id: Optional[str] = None) -> ChatMessageResponse:
    """Save a chat message to the database and return the response."""
    msg_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    final_user_id = user_id if user_id and user_id.strip() else "local_user"
    final_session = session_id if session_id and session_id.strip() else None

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO chat_messages (id, user_id, session_id, role, content, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (msg_id, final_user_id, final_session, role, content, now))
    conn.commit()
    conn.close()

    return ChatMessageResponse(
        id=msg_id,
        user_id=final_user_id,
        role=role,
        content=content,
        created_at=now,
        session_id=final_session,
    )


def run_prediction(
    binary_features: list,
    multi_features_dict: dict,
    source_ip: str,
    protocol: str,
    user_id: str,
    device_id: str,
    extra_features: Optional[DetectionFeatures] = None,
) -> PredictionResult:
    """
    Run the two-stage prediction pipeline and return a structured result.

    Stage 1: Binary classifier — attack vs normal
    Stage 2: Multi-class classifier — identify attack type
    """
    if not MODELS_LOADED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML models are not loaded. Please check server logs."
        )

    # ── Stage 1: Binary Detection ──
    X_bin = pd.DataFrame([binary_features], columns=feature_names_bin)
    proba = model_binary.predict_proba(X_bin)[0][1]
    is_attack = 1 if proba >= 0.35 else 0
  

    try:
        binary_proba = model_binary.predict_proba(X_bin)[0]
        binary_confidence = float(np.max(binary_proba)) * 100  # Convert to percentage
    except Exception:
        binary_confidence = None

    # Build features object (use provided or create default)
    features = extra_features or DetectionFeatures(
        protocol=protocol.upper() if protocol else "N/A",
        source_ip=source_ip,
    )

    if is_attack == 0:
        result = PredictionResult(
            is_attack=False,
            attack_type="Normal",
            severity="None",
            confidence=binary_confidence,
            binary_confidence=binary_confidence,
            code=-1,
            solution="",
            features=features,
        )
    else:
        # ── Stage 2: Multi-Class Classification ──
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

        X_multi = pd.DataFrame([multi_row], columns=scaler_features)
        X_scaled = scaler.transform(X_multi)

        pred_num = model_multi.predict(X_scaled)[0]
        attack_type_str = label_encoder_multi.inverse_transform([pred_num])[0]
        severity = severity_map.get(attack_type_str, Severity.MEDIUM)
        solution = solutions_map.get(attack_type_str, "")

        try:
            proba = model_multi.predict_proba(X_scaled)[0]
            confidence = float(np.max(proba)) * 100  # Convert to percentage
        except Exception:
            confidence = None

        result = PredictionResult(
            is_attack=True,
            attack_type=attack_type_str,
            severity=severity.value if isinstance(severity, Severity) else str(severity),
            confidence=confidence,
            binary_confidence=binary_confidence,
            code=int(pred_num),
            solution=solution,
            features=features,
        )

    # ── Persist to SQLite ──
    try:
        should_save = result.is_attack
        if not should_save:
            normal_counter[0] += 1
            if normal_counter[0] % 10 == 0:
                should_save = True

        if should_save:
            final_user_id = user_id if (user_id and user_id.strip()) else "local_user"
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO detection_logs 
                (id, user_id, detected_at, source_ip, status, attack_type, protocol, severity, confidence, solution, device_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                final_user_id,
                datetime.now(timezone.utc).isoformat(),
                source_ip,
                "detected" if result.is_attack else "normal",
                result.attack_type,
                protocol,
                result.severity,
                result.confidence if result.confidence else 0.0,
                result.solution,
                device_id,
            ))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"SQLite insert error: {e}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# WIRESHARK FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def wireshark_row_to_features(row: dict) -> tuple[list, dict, str, DetectionFeatures]:
    """
    Extract features from a Wireshark row dictionary.
    Returns: (binary_features, multi_features, protocol, detection_features)
    """
    protocol = str(row.get("Protocol", "TCP")).strip()

    # TCP Flags
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

    # IP Flags
    ip_flags_str = str(row.get("IP Flags", "0x00")).lower()
    ip_flag_df = 1.0 if "0x40" in ip_flags_str else 0.0
    ip_flag_mf = 1.0 if "0x20" in ip_flags_str else 0.0
    ip_flag_none = 1.0 if ip_flags_str in ["0x00", "0", "0x00,0x00"] else 0.0

    # Protocol indicators
    proto_up = protocol.upper()
    is_tcp = 1.0 if "TCP" in proto_up else 0.0
    is_udp = 1.0 if "UDP" in proto_up else 0.0
    is_icmp = 1.0 if "ICMP" in proto_up else 0.0

    # TTL analysis
    ttl = safe_float(str(row.get("IP TTL", 64)).split(",")[0])
    is_common_ttl = 1.0 if ttl in COMMON_TTLS else 0.0
    ttl_anomaly = 1.0 if ttl < 10 or ttl > 200 else 0.0
    ttl_dev = float(min(abs(ttl - c) for c in COMMON_TTLS))

    # Ports
    tcp_src_port = safe_float(row.get("TCP Source Port", -1))
    tcp_dst_port = safe_float(row.get("TCP Destination Port", -1))
    udp_src_port = safe_float(row.get("UDP Source Port", 0))
    udp_dst_port = safe_float(row.get("UDP Destination Port", 0))

    # Packet size
    length = safe_float(row.get("Length", 0))
    small_pkt = 1.0 if length < 64 else 0.0
    medium_pkt = 1.0 if 64 <= length <= 1500 else 0.0
    large_pkt = 1.0 if length > 1500 else 0.0

    # HTTP analysis
    http_method = str(row.get("HTTP Request Method", "") or "").strip()
    http_uri = str(row.get("HTTP Request URI", "") or "").strip()
    http_version = str(row.get("HTTP Request Version", "") or "").strip()
    http_resp_code = str(row.get("HTTP Response Code", "") or "").strip()
    http_ua = str(row.get("HTTP User-Agent", "") or "").lower()
    http_ct = str(row.get("HTTP Content Type", "") or "").lower()
    http_cl = safe_float(row.get("HTTP Content-Length", 0))

    is_http_request = 1.0 if http_method else 0.0
    is_http_response = 1.0 if http_resp_code else 0.0
    is_http_1_0 = 1.0 if "1.0" in http_version else 0.0

    is_2xx = is_3xx = is_4xx = is_5xx = 0.0
    is_http_success = is_http_error = 0.0
    if http_resp_code:
        if http_resp_code.startswith("2"): is_2xx = is_http_success = 1.0
        elif http_resp_code.startswith("3"): is_3xx = 1.0
        elif http_resp_code.startswith("4"): is_4xx = is_http_error = 1.0
        elif http_resp_code.startswith("5"): is_5xx = is_http_error = 1.0

    is_suspicious_method = 1.0 if http_method in ["POST", "OPTIONS", "PROPFIND"] else 0.0

    uri_low = http_uri.lower()
    full_uri = str(row.get("HTTP Full URI", "") or "").lower()
    uri_length = float(len(http_uri))
    uri_path_depth = float(http_uri.count("/"))
    uri_has_params = 1.0 if "?" in http_uri else 0.0
    uri_has_special = 1.0 if any(c in http_uri for c in ["<",">",'"',"'",";","(",")","{"]) else 0.0

    is_sqli_path = 1.0 if any(k in uri_low for k in ["'","union","select","drop","insert","or 1=1"]) else 0.0
    is_system_file_attack = 1.0 if any(k in uri_low for k in ["etc/passwd","win.ini","../","..\\"]) else 0.0
    has_path_traversal = 1.0 if "../" in http_uri or "..\\" in http_uri else 0.0
    has_admin = 1.0 if "admin" in uri_low else 0.0

    combined_uri = full_uri + uri_low
    has_sql = 1.0 if any(k in combined_uri for k in ["select ","union ","drop ","insert ","delete from","' or"]) else 0.0
    has_xss = 1.0 if any(k in combined_uri for k in ["<script","javascript:","onerror=","onload=","alert("]) else 0.0

    is_attack_tool = 1.0 if any(k in http_ua for k in ["sqlmap","ffuf","fuzz","apachebench","nmap","nikto","masscan","hydra","metasploit"]) else 0.0
    is_browser = 1.0 if any(k in http_ua for k in ["mozilla","chrome","firefox","safari","edge"]) else 0.0
    is_script = 1.0 if any(k in http_ua for k in ["python","curl","wget","requests","go-http"]) else 0.0
    is_bot = 1.0 if any(k in http_ua for k in ["bot","crawler","spider","scraper"]) else 0.0

    is_html = 1.0 if "html" in http_ct else 0.0
    is_text = 1.0 if "text" in http_ct else 0.0
    is_binary = 1.0 if "octet-stream" in http_ct else 0.0
    is_image = 1.0 if "image" in http_ct else 0.0
    is_form = 1.0 if "form" in http_ct else 0.0

    has_dns_query = 1.0 if str(row.get("DNS Query Name", "") or "").strip() else 0.0

    icmp_type = safe_float(row.get("ICMP Type", -1))
    is_icmp_echo = 1.0 if icmp_type == 8 else 0.0
    is_icmp_reply = 1.0 if icmp_type == 0 else 0.0
    is_icmp_unreachable = 1.0 if icmp_type == 3 else 0.0

    deltatime = safe_float(row.get("deltatime", 0))
    is_zero_deltatime = 1.0 if deltatime < 0.0001 else 0.0
    pps = min(1.0 / max(deltatime, 0.0001), 10000.0)
    packet_rate = pps
    icmp_rate = pps if is_icmp else 0.0
    icmp_suspicious = 1.0 if (is_icmp and icmp_rate > 50) else 0.0
    is_fast_traffic = 1.0 if pps > 100 else 0.0

    tcp_stream = safe_float(row.get("TCP Stream", 0))
    tcp_seq = safe_float(row.get("TCP Sequence Number", 0))
    tcp_ack_num = safe_float(row.get("TCP Acknowledgment Number", 0))
    tcp_window = safe_float(row.get("TCP Window Size", 0))

    is_fragmented = 1.0 if safe_float(row.get("IP Fragment Offset", 0)) > 0 else 0.0
    syn_ratio = tcp_syn

    ip_length = safe_float(row.get("IP Length", 0))

    all_f = {
        "Protocol": encode_protocol(protocol),
        "Length": length,
        "IP Length": ip_length,
        "IP TTL": ttl,
        "TCP Source Port": tcp_src_port,
        "TCP Destination Port": tcp_dst_port,
        "TCP Sequence Number": tcp_seq,
        "TCP Acknowledgment Number": tcp_ack_num,
        "TCP SYN Flag": tcp_syn,
        "TCP ACK Flag": tcp_ack,
        "TCP FIN Flag": tcp_fin,
        "TCP RST Flag": tcp_rst,
        "TCP Window Size": tcp_window,
        "TCP Stream": tcp_stream,
        "UDP Source Port": udp_src_port,
        "UDP Destination Port": udp_dst_port,
        "ICMP Type": icmp_type,
        "deltatime": deltatime,
        "is_http_response": is_http_response,
        "is_2xx": is_2xx,
        "is_3xx": is_3xx,
        "is_4xx": is_4xx,
        "is_5xx": is_5xx,
        "is_http_success": is_http_success,
        "is_http_request": is_http_request,
        "is_suspicious_method": is_suspicious_method,
        "is_attack_tool": is_attack_tool,
        "is_browser": is_browser,
        "is_script": is_script,
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
        "is_http_1_0": is_http_1_0,
        "has_dns_query": has_dns_query,
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
        "tcp_rst": tcp_rst,
        "tcp_psh": tcp_psh,
        "tcp_urg": tcp_urg,
        "has_ip_source": 1.0 if row.get("IP Source") else 0.0,
        "has_ip_dest": 1.0 if row.get("IP Destination") else 0.0,
        "ip_flag_df": ip_flag_df,
        "ip_flag_mf": ip_flag_mf,
        "ip_flag_none": ip_flag_none,
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
    multi_f = {f: float(all_f.get(f, 0.0)) for f in scaler_features}

    # Build DetectionFeatures for Frontend
    src_ip = str(row.get("IP Source", row.get("Source", "0.0.0.0")))
    det_features = build_detection_features(
        protocol=protocol,
        source_ip=src_ip,
        tcp_dst_port=tcp_dst_port,
        tcp_src_port=tcp_src_port,
        udp_dst_port=udp_dst_port,
        udp_src_port=udp_src_port,
        length=length,
        ttl=ttl,
    )

    return binary_f, multi_f, protocol, det_features


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS — ROOT & HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_model=ApiResponse)
def root() -> ApiResponse:
    """API root endpoint — returns basic API information."""
    return ApiResponse.ok(
        data=ApiInfo(
            message="CyberShield AI API (SQLite Local Version)",
            version="1.1.0",
            endpoints=[
                "/health",
                "/features",
                "/predict",
                "/predict/full",
                "/predict/wireshark-row",
                "/predict/csv-row",
                "/api/agent",
                "/api/logs",
                "/api/chat/history",
                "/api/chat/message",
                "/api/stats/overview",
                "/api/stats/timeline",
                "/docs",
            ],
            documentation="/docs",
        ),
        message="Welcome to CyberShield AI API",
    )


@app.get("/health", response_model=ApiResponse)
def health_check() -> ApiResponse:
    """Health check endpoint — verify API and model status."""
    db_status = "connected"
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("SELECT 1")
        conn.close()
    except Exception as e:
        db_status = f"error: {str(e)}"

    return ApiResponse.ok(
        data=HealthStatus(
            status="CyberShield AI API is running with SQLite",
            version="1.1.0",
            binary_features=len(feature_names_bin) if MODELS_LOADED else 0,
            scaler_features=len(scaler_features) if MODELS_LOADED else 0,
            top_protocols=top_protocols if MODELS_LOADED else [],
            database=db_status,
            models_loaded=MODELS_LOADED,
        ),
        message="System healthy",
    )


@app.get("/features", response_model=ApiResponse)
def get_features() -> ApiResponse:
    """Return the feature names used by the ML models."""
    if not MODELS_LOADED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Models not loaded"
        )
    return ApiResponse.ok(
        data=FeaturesInfo(
            binary_features=list(feature_names_bin),
            multi_features=scaler_features,
            top_protocols=top_protocols,
        ),
        message="Features retrieved successfully",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS — PREDICTION
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/predict", response_model=ApiResponse)
def predict_legacy(flow: NetworkFlowLegacy) -> ApiResponse:
    """
    Legacy prediction endpoint — accepts a flat feature list.
    Maintained for backward compatibility.
    """
    try:
        multi_dict = {feat: flow.features[i] for i, feat in enumerate(feature_names_bin)}
        result = run_prediction(
            binary_features=flow.features,
            multi_features_dict=multi_dict,
            source_ip=flow.source_ip,
            protocol=flow.protocol,
            user_id=flow.user_id,
            device_id=flow.device_id,
        )
        return ApiResponse.ok(data=result, message="Prediction completed")
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/predict/full", response_model=ApiResponse)
def predict_full(flow: NetworkFlow) -> ApiResponse:
    """
    Full prediction endpoint — accepts separate binary and multi-class features.
    This is the primary endpoint for the Detection Overlay.
    """
    try:
        result = run_prediction(
            binary_features=flow.binary_features,
            multi_features_dict=flow.multi_features,
            source_ip=flow.source_ip,
            protocol=flow.protocol,
            user_id=flow.user_id,
            device_id=flow.device_id,
        )
        return ApiResponse.ok(data=result, message="Full prediction completed")
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/predict/wireshark-row", response_model=ApiResponse)
def predict_wireshark_row(row: WiresharkRow) -> ApiResponse:
    """
    Predict from a single Wireshark-exported row.
    Automatically extracts all relevant features from the row.
    """
    try:
        row_dict = row.model_dump(by_alias=True)
        binary_f, multi_f, protocol, det_features = wireshark_row_to_features(row_dict)
        src_ip = str(row_dict.get("IP Source", row_dict.get("Source", "0.0.0.0")))
        user_id = str(row_dict.get("user_id", ""))

        result = run_prediction(
            binary_features=binary_f,
            multi_features_dict=multi_f,
            source_ip=src_ip,
            protocol=protocol,
            user_id=user_id,
            device_id="wireshark-import",
            extra_features=det_features,
        )
        return ApiResponse.ok(data=result, message="Wireshark row predicted")
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/predict/csv-row", response_model=ApiResponse)
def predict_csv_row(row: CSVRow) -> ApiResponse:
    """
    Predict from a single CSV row.
    Dynamically maps CSV columns to model features.
    """
    try:
        row_dict = row.model_dump()
        binary_features = [float(row_dict.get(f, 0) or 0) for f in feature_names_bin]
        multi_dict = {f: float(row_dict.get(f, 0) or 0) for f in scaler_features}
        protocol = str(row_dict.get("Protocol", "TCP"))

        result = run_prediction(
            binary_features=binary_features,
            multi_features_dict=multi_dict,
            source_ip=str(row_dict.get("IP Source", row_dict.get("source_ip", "0.0.0.0"))),
            protocol=protocol,
            user_id=str(row_dict.get("user_id", "")),
            device_id=str(row_dict.get("device_id", "")),
        )
        return ApiResponse.ok(data=result, message="CSV row predicted")
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS — DETECTION LOGS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/logs", response_model=ApiResponse)
def get_logs(
    limit: int = Query(default=50, ge=1, le=500, description="Maximum records to return"),
    offset: int = Query(default=0, ge=0, description="Number of records to skip"),
    severity: Optional[str] = Query(default=None, description="Filter by severity level"),
    attack_type: Optional[str] = Query(default=None, description="Filter by attack type"),
    protocol: Optional[str] = Query(default=None, description="Filter by protocol"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP"),
    start_date: Optional[str] = Query(default=None, description="Filter from date (ISO 8601)"),
    end_date: Optional[str] = Query(default=None, description="Filter to date (ISO 8601)"),
) -> ApiResponse:
    """
    Get detection logs with pagination and filtering.
    Returns the most recent detections first.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM detection_logs WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if start_date:
            query += " AND detected_at >= ?"
            params.append(start_date)
        if end_date:
            query += " AND detected_at <= ?"
            params.append(end_date)

        query += " ORDER BY detected_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        logs = [DetectionLog(**dict(row)).model_dump() for row in rows]
        return ApiResponse.ok(data=logs, message=f"Retrieved {len(logs)} logs")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS — AI SECURITY ASSISTANT (SENTINELAI)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/agent", response_model=ApiResponse)
async def sentinel_agent(request: AgentRequest) -> ApiResponse:
    """
    SentinelAI Security Assistant — provides AI-powered security analysis.

    Modes:
    - chat: Conversational security assistance with context from recent logs
    - summary: Generate an executive incident report

    Messages are persisted to the chat history database.
    """
    try:
        messages = request.messages
        mode = request.mode
        logs = request.logs
        user_id = request.user_id or "local_user"
        session_id = request.session_id

        KEY = os.environ.get("LOVABLE_API_KEY")

        # ── Fallback mode when no API key is configured ──
        if not KEY:
            if mode == "summary":
                reply_text = (
                    "## Executive Summary\n"
                    "SentinelAI has detected low-to-medium risk network anomalies over the local session. "
                    "Traffic volume is stable.\n\n"
                    "## Top Threats\n"
                    "- Port scanning attempts from local mock framework.\n\n"
                    "## Recommended Actions (numbered, prioritized)\n"
                    "1. Enable strict local firewall filtering.\n"
                    "2. Review system access credentials.\n\n"
                    "## Response Playbook\n"
                    "Standard perimeter containment rules have been applied automatically."
                )
            else:
                reply_text = (
                    "Hello! I am SentinelAI, running in local preview mode because LOVABLE_API_KEY "
                    "is not configured yet. Your SQLite logging and models are active and running perfectly!"
                )

            # Save AI reply to chat history
            if session_id:
                save_chat_message(user_id=user_id, role="assistant", content=reply_text, session_id=session_id)

            return ApiResponse.ok(
                data=AgentResponse(
                    message=reply_text,
                    role="assistant",
                    mode=mode,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    session_id=session_id,
                ),
                message="SentinelAI response (local fallback mode)",
            )

        # ── Build context from recent logs ──
        ctx = "No recent detections available."
        if logs:
            ctx_lines = []
            for log in logs[:25]:
                ctx_lines.append(
                    f"- [{log.get('severity', 'Unknown')}] {log.get('attack_type', 'Unknown')} "
                    f"via {log.get('protocol', 'Unknown')} from {log.get('source_ip', 'Unknown')} "
                    f"(conf {log.get('confidence', 0)}%)"
                )
            ctx = "Recent detections (most recent first):\n" + "\n".join(ctx_lines)

        system_chat = (
            f"You are SentinelAI, a senior SOC analyst. Be concise, technical, and actionable.\n"
            f"You have access to recent detection telemetry below. Reference specific events when relevant.\n{ctx}"
        )
        system_summary = (
            f"You are SentinelAI. Generate a crisp incident report from the telemetry below.\n"
            f"Output sections: ## Executive Summary, ## Top Threats, "
            f"## Recommended Actions (numbered, prioritized), ## Response Playbook.\nTelemetry:\n{ctx}"
        )

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
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"AI gateway error: {response.status_code}"
                )

            ai_response = response.json()
            reply_text = ai_response["choices"][0]["message"]["content"]

        # Save AI reply to chat history
        if session_id:
            save_chat_message(user_id=user_id, role="assistant", content=reply_text, session_id=session_id)

        return ApiResponse.ok(
            data=AgentResponse(
                message=reply_text,
                role="assistant",
                mode=mode,
                timestamp=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
            ),
            message="SentinelAI response",
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS — CHAT HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/chat/message", response_model=ApiResponse)
def save_message(request: ChatMessageRequest) -> ApiResponse:
    """Save a chat message to the database."""
    try:
        result = save_chat_message(
            user_id=request.user_id,
            role=request.role,
            content=request.content,
            session_id=request.session_id,
        )
        return ApiResponse.ok(data=result, message="Message saved")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/chat/history", response_model=ApiResponse)
def get_chat_history(
    user_id: str = Query(default="local_user", description="User identifier"),
    session_id: Optional[str] = Query(default=None, description="Session filter"),
    limit: int = Query(default=100, ge=1, le=500, description="Maximum messages"),
) -> ApiResponse:
    """Get chat history for a user or session."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM chat_messages WHERE user_id = ?"
        params = [user_id]

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        query += " ORDER BY created_at ASC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        messages = [ChatMessageResponse(**dict(row)).model_dump() for row in rows]
        return ApiResponse.ok(data=messages, message=f"Retrieved {len(messages)} messages")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.delete("/api/chat/history", response_model=ApiResponse)
def clear_chat_history(
    user_id: str = Query(default="local_user", description="User identifier"),
    session_id: Optional[str] = Query(default=None, description="Session to clear"),
) -> ApiResponse:
    """Clear chat history for a user or specific session."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        if session_id:
            cursor.execute(
                "DELETE FROM chat_messages WHERE user_id = ? AND session_id = ?",
                (user_id, session_id)
            )
        else:
            cursor.execute(
                "DELETE FROM chat_messages WHERE user_id = ?",
                (user_id,)
            )

        conn.commit()
        deleted = cursor.rowcount
        conn.close()

        return ApiResponse.ok(data={"deleted": deleted}, message=f"Cleared {deleted} messages")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS — ANALYTICS & STATISTICS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/stats/overview", response_model=ApiResponse)
def get_stats_overview() -> ApiResponse:
    """Get dashboard overview statistics."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Total detections
        cursor.execute("SELECT COUNT(*) FROM detection_logs")
        total_detections = cursor.fetchone()[0]

        # Total attacks (excluding Normal)
        cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE attack_type != 'Normal'")
        total_attacks = cursor.fetchone()[0]

        # Total normal
        cursor.execute("SELECT COUNT(*) FROM detection_logs WHERE attack_type = 'Normal'")
        total_normal = cursor.fetchone()[0]

        # Severity breakdown
        cursor.execute("SELECT severity, COUNT(*) FROM detection_logs GROUP BY severity")
        severity_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

        # Attack type breakdown
        cursor.execute("SELECT attack_type, COUNT(*) FROM detection_logs GROUP BY attack_type")
        attack_type_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

        # Last detection
        cursor.execute("SELECT detected_at FROM detection_logs ORDER BY detected_at DESC LIMIT 1")
        row = cursor.fetchone()
        last_detection_at = row[0] if row else None

        conn.close()

        return ApiResponse.ok(
            data=StatsOverview(
                total_detections=total_detections,
                total_attacks=total_attacks,
                total_normal=total_normal,
                severity_breakdown=severity_breakdown,
                attack_type_breakdown=attack_type_breakdown,
                last_detection_at=last_detection_at,
            ),
            message="Statistics overview retrieved",
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/stats/timeline", response_model=ApiResponse)
def get_stats_timeline(
    days: int = Query(default=30, ge=1, le=365, description="Number of days to look back"),
) -> ApiResponse:
    """Get detection timeline for charting — daily counts."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT 
                DATE(detected_at) as date,
                COUNT(*) as count,
                SUM(CASE WHEN attack_type != 'Normal' THEN 1 ELSE 0 END) as attacks
            FROM detection_logs
            WHERE detected_at >= DATE('now', '-%s days')
            GROUP BY DATE(detected_at)
            ORDER BY date ASC
        ''' % days)

        rows = cursor.fetchall()
        conn.close()

        timeline = [
            TimelinePoint(date=row[0], count=row[1], attacks=row[2]).model_dump()
            for row in rows
        ]

        return ApiResponse.ok(data=timeline, message=f"Timeline for last {days} days")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/stats/attack-types", response_model=ApiResponse)
def get_attack_type_stats(
    limit: int = Query(default=20, ge=1, le=100, description="Top N attack types"),
) -> ApiResponse:
    """Get attack type distribution for charts."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT attack_type, COUNT(*) as count
            FROM detection_logs
            WHERE attack_type != 'Normal'
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT ?
        ''', (limit,))

        rows = cursor.fetchall()
        conn.close()

        stats = [{"attack_type": row[0], "count": row[1]} for row in rows]
        return ApiResponse.ok(data=stats, message="Attack type statistics retrieved")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    print("Starting CyberShield API v1.1.0 with SQLite support...")
    uvicorn.run(app, host="127.0.0.1", port=8000)