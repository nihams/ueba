import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import json

def create_peer_groups(num_clusters=4):
    """
    Reads user features and clusters them into peer groups using K-Means.
    """
    print("Loading user features...")
    try:
        df = pd.read_csv('user_features.csv')
    except FileNotFoundError:
        print("Error: 'user_features.csv' not found. Please run 'build_features.py' first.")
        return
        
    user_ids = df['user_id']
    # Select only the numeric feature columns for clustering
    features = df.drop('user_id', axis=1)

    # Scale features for better clustering performance (very important for K-Means)
    print("Scaling features...")
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    # Perform K-Means clustering
    print(f"Running K-Means to find {num_clusters} peer groups...")
    kmeans = KMeans(n_clusters=num_clusters, random_state=42, n_init='auto')
    df['peer_group'] = kmeans.fit_predict(scaled_features)

    # Save the mapping of user to peer group
    user_to_group = pd.Series(df.peer_group.values, index=df.user_id).to_dict()
    
    output_path = 'user_to_peer_group.json'
    with open(output_path, 'w') as f:
        json.dump(user_to_group, f, indent=2)
    
    print(f"Peer group assignments saved to {output_path}")
    print("\nExample assignments:")
    print(df[['user_id', 'peer_group']].head())


if __name__ == "__main__":
    # You can experiment with the number of clusters
    create_peer_groups(num_clusters=4)