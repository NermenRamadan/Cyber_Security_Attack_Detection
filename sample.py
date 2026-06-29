import pandas as pd
import joblib

feature_names = joblib.load(r'F:\DEPI\final_one\pulse-detect-net-main\notebook\models\feature_names_binary.pkl')


cols = feature_names + ['label']

df = pd.read_csv(
    r'F:\DEPI\final_one\data\merged_dataset.csv',
    usecols=cols,
    low_memory=False,
    nrows=5000
)

sample = df.groupby('label', group_keys=False).apply(lambda x: x.sample(min(10, len(x)), random_state=42))
sample.to_csv(r'F:\DEPI\final_one\test_sample.csv', index=False)
print("Done! Rows:", len(sample))
print("Labels:", sample['label'].value_counts().to_dict())