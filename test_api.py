import pandas as pd
import requests
import joblib

feature_names = joblib.load(r'F:\DEPI\final_one\pulse-detect-net-main\notebook\models\feature_names_binary.pkl')

df = pd.read_csv(r'F:\DEPI\final_one\data\merged_dataset.csv', low_memory=False)

for label in df['label'].unique():
    row = df[df['label'] == label][feature_names].dropna().head(1)
    if row.empty:
        continue
    features = row.iloc[0].tolist()
    res = requests.post(
        "http://127.0.0.1:8000/predict",
        json={
            "features": features,
            "source_ip": "192.168.1.1",
            "device_id": "test-device",
            "user_id": ""
        }
    )
    result = res.json()
    print(f"Real: {label:20} → Predicted: {result['attack_type']:20} | Confidence: {result['confidence']:.2%}")