
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
import json
from sklearn.decomposition import IncrementalPCA
from sklearn.cluster import MiniBatchKMeans
import numpy as np
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

# Load features
with open('features.json', 'r') as f:
    features_data = json.load(f)
    features = features_data['features']
    target = features_data['target']

# Load datasets
try:
    print("Loading datasets...")
    train_df = pd.read_csv('train.csv')
    test_df = pd.read_csv('test.csv')
    valid_df = pd.read_csv('valid.csv')
    print("Datasets loaded successfully.")
except FileNotFoundError as e:
    print(f"Error loading data: {e}")
    exit()

# Prepare data
print("Preparing data...")
X_train = train_df[features]
y_train = train_df[target]

X_test = test_df[features]
y_test = test_df[target]

X_valid = valid_df[features]
y_valid = valid_df[target]

# Scale features
print("Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
X_valid_scaled = scaler.transform(X_valid)

# Dimensionality Reduction and Clustering (Train Only)
print("Applying IPCA...")
batch_size = 1024
n_components = 10  # Example: reduce to 10 dimensions
ipca = IncrementalPCA(n_components=n_components, batch_size=batch_size)

# Process in batches for IPCA
for i in range(0, X_train_scaled.shape[0], batch_size):
    batch = X_train_scaled[i:i+batch_size]
    ipca.partial_fit(batch)

X_train_pca = ipca.transform(X_train_scaled)

# Apply KMeans clustering on PCA-reduced data
print("Applying MiniBatchKMeans...")
n_clusters = 8  # Example: 8 clusters
kmeans = MiniBatchKMeans(n_clusters=n_clusters, batch_size=batch_size, n_init=10)
kmeans.fit(X_train_pca)

# Add cluster labels to the training dataframe
train_df['cluster'] = kmeans.labels_

# Cluster-to-Protocol Mapping (Train Only)
with open('cluster_protocol_map.json', 'r') as f:
    cluster_to_protocol = json.load(f)

# Remove Sparse Clusters (Train Only)
cluster_counts = train_df['cluster'].value_counts()
sparse_clusters = cluster_counts[cluster_counts < 2].index

if not sparse_clusters.empty:
    train_df = train_df[~train_df['cluster'].isin(sparse_clusters)]
    print(f"Removed sparse clusters: {sparse_clusters.tolist()}")
else:
    print("No sparse clusters found.")

# Train/Validation Split (Stratified)
X = train_df[features]
y = train_df[target]
clusters = train_df['cluster']

X_train, X_valid, y_train, y_valid = train_test_split(
    X, y, test_size=0.15, stratify=clusters, random_state=42
)

# Scale features again after split
X_train_scaled = scaler.fit_transform(X_train)
X_valid_scaled = scaler.transform(X_valid)

# Handle Imbalanced Classes with SMOTE
smote = SMOTE(random_state=42)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train_scaled, y_train)

# Train the Classifier
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=2)
rf.fit(X_train_resampled, y_train_resampled)

# Prepare the Test Data for Evaluation
X_test_pca = ipca.transform(X_test_scaled)
test_df['cluster'] = kmeans.predict(X_test_pca)
test_df['protocol'] = test_df['cluster'].map(cluster_to_protocol)

# Evaluate model
print("Test set evaluation:")
y_pred_test = rf.predict(X_test_scaled)
print(accuracy_score(y_test, y_pred_test))
print(classification_report(y_test, y_pred_test))

print("Validation set evaluation:")
y_pred_valid = rf.predict(X_valid_scaled)
print(accuracy_score(y_valid, y_pred_valid))
print(classification_report(y_valid, y_pred_valid))

# Build and Save the Final Model Object
final_model = {
    'preprocessor': scaler,
    'pca': ipca,
    'kmeans': kmeans,
    'classifier': rf,
    'cluster_protocol_map': cluster_to_protocol
}

joblib.dump(final_model, 'nids_model_cpu.pkl')

print("Final model saved to nids_model_cpu.pkl")
