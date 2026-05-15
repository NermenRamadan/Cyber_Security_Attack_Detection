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

load_dotenv()
warnings.filterwarnings("ignore")

app = FastAPI(title="CyberShield AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_PATH = r"F:\DEPI\final_one\pulse-detect-net-main\notebook\models"

# Supabase
SUPABASE_URL = "https://uodjrpkqebgcsbborbsj.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

try:
    sb = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_KEY else None
    if sb:
        print("Supabase connected successfully")
    else:
        print("WARNING: SUPABASE_SERVICE_KEY not found in .env!")
except Exception as e:
    print(f"Supabase connection error: {e}")
    sb = None

try:
    model_binary        = joblib.load(os.path.join(BASE_PATH, "model_binary.pkl"))
    model_multi         = joblib.load(os.path.join(BASE_PATH, "model_multi.pkl"))
    scaler              = joblib.load(os.path.join(BASE_PATH, "scaler.pkl"))
    label_encoder_multi = joblib.load(os.path.join(BASE_PATH, "label_encoder_multi.pkl"))
    feature_names_bin   = joblib.load(os.path.join(BASE_PATH, "feature_names_binary.pkl"))
    print("Models loaded successfully")
except Exception as e:
    print(f"Error loading models: {e}")
    exit(1)

severity_map = {
    "DDoS_ICMP": "Critical", "DDoS_UDP": "Critical",
    "DDoS_RAW": "Critical", "SYN_Flood": "Critical",
    "ICMP_Flood": "Critical", "DoS": "High",
    "SSH_BruteForce": "High", "FTP_BruteForce": "High",
    "FTP_Exploit": "High", "RCE": "High",
    "SQL_Injection": "High", "XSS": "Medium",
    "Fuzzing": "Medium", "PortScanning": "Medium",
    "MITM_ARP": "Medium", "Normal": "None",
}

solutions_map = {
    "DDoS_ICMP": "Enable rate limiting and activate WAF/CDN scrubbing.",
    "DDoS_UDP": "Block UDP flood at firewall level.",
    "DDoS_RAW": "Enable DDoS protection and contact ISP.",
    "SYN_Flood": "Enable SYN cookies on the server.",
    "ICMP_Flood": "Block ICMP at perimeter firewall.",
    "DoS": "Enable rate limiting and throttling.",
    "SSH_BruteForce": "Lock account, enable MFA, throttle login attempts.",
    "FTP_BruteForce": "Lock account, disable FTP if unused.",
    "FTP_Exploit": "Patch FTP server, use SFTP instead.",
    "RCE": "Patch vulnerable service immediately.",
    "SQL_Injection": "Use parameterized queries and input validation.",
    "XSS": "Sanitize user input and enforce Content Security Policy.",
    "Fuzzing": "Implement input validation and WAF rules.",
    "PortScanning": "Block source IP at firewall.",
    "MITM_ARP": "Enforce HSTS/TLS, rotate certificates.",
}

# عداد للـ normal packets عشان منحفظش كل باكيت
normal_counter = [0]

class NetworkFlow(BaseModel):
    features: list[float]
    source_ip: str = "0.0.0.0"
    protocol: str = "TCP"
    user_id: str = ""
    device_id: str = ""

@app.get("/health")
def health_check():
    return {
        "status": "CyberShield API is running",
        "supabase": "connected" if sb else "disconnected"
    }

@app.post("/predict")
def predict(flow: NetworkFlow):
    try:
        # STEP 1: Binary Classification
        X_bin = pd.DataFrame([flow.features], columns=feature_names_bin)
        is_attack = int(model_binary.predict(X_bin)[0])

        try:
            binary_proba = model_binary.predict_proba(X_bin)[0]
            binary_confidence = float(np.max(binary_proba))
        except:
            binary_confidence = None

        if is_attack == 0:
            result = {
                "is_attack": False,
                "attack_type": "Normal",
                "severity": "None",
                "confidence": binary_confidence,
                "code": -1,
                "solution": ""
            }
        else:
            # STEP 2: Multiclass Classification
            multi_features = scaler.feature_names_in_
            X_multi = pd.DataFrame([[0] * len(multi_features)], columns=multi_features)
            for col in feature_names_bin:
                if col in X_multi.columns:
                    X_multi[col] = X_bin[col].values

            X_scaled = scaler.transform(X_multi)
            pred_num = model_multi.predict(X_scaled)[0]
            attack_type = label_encoder_multi.inverse_transform([pred_num])[0]
            severity = severity_map.get(attack_type, "Medium")
            solution = solutions_map.get(attack_type, "")

            try:
                confidence = float(np.max(model_multi.predict_proba(X_scaled)[0]))
            except:
                confidence = None

            result = {
                "is_attack": True,
                "attack_type": attack_type,
                "severity": severity,
                "confidence": confidence,
                "code": int(pred_num),
                "solution": solution
            }

        # حفظ في Supabase
        if sb:
            try:
                should_save = False

                if result["is_attack"]:
                    # الهجمات دايماً بنحفظها فوراً
                    should_save = True
                else:
                    # الـ Normal بنحفظ 1 من كل 10 عشان منملاش الـ DB
                    normal_counter[0] += 1
                    if normal_counter[0] % 10 == 0:
                        should_save = True

                if should_save:
                    final_user_id = flow.user_id if (flow.user_id and flow.user_id.strip() != "") else None

                    sb.table("detection_logs").insert({
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                        "source_ip": flow.source_ip,
                        "status": "detected" if result["is_attack"] else "normal",
                        "attack_type": result["attack_type"],
                        "protocol": flow.protocol,
                        "severity": result["severity"],
                        "confidence": result["confidence"],
                        "solution": result["solution"],
                        "user_id": final_user_id,
                        "device_id": flow.device_id,
                    }).execute()

                    if result["is_attack"]:
                        print(f"[SAVED] ATTACK: {result['attack_type']} | {result['severity']} | src: {flow.source_ip}")
                    else:
                        print(f"[SAVED] Normal packet #{normal_counter[0]} | src: {flow.source_ip}")

            except Exception as e:
                print(f"Supabase insert error: {e}")

        return result

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def root():
    return {
        "message": "CyberShield AI API",
        "endpoints": ["/health", "/predict", "/docs"]
    }

if __name__ == "__main__":
    import uvicorn
    print("Starting CyberShield API...")
    uvicorn.run(app, host="127.0.0.1", port=8000)