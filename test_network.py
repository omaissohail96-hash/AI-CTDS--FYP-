import pandas as pd
from detectors.network_detectors import predict_network

df = pd.read_csv("datasets/intrusion/data.csv")

# Pick a REAL network flow
row = df.sample(1)

# Convert row to dictionary
flow_features = row.to_dict(orient="records")[0]

result, confidence = predict_network(flow_features)

print("Prediction:", result)
print("Confidence:", confidence, "%")
