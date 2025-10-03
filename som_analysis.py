import pandas as pd
import numpy as np
from minisom import MiniSom
import matplotlib.pyplot as plt
from pathlib import Path
from collections import Counter

def run_som_analysis(user_features_path='user_features.csv', output_image_path='som_u_matrix.png'):
    """
    Performs an advanced SOM analysis using quantization error and a multi-epoch 
    strategy to robustly identify outliers.
    """
    print(f"Starting Advanced SOM analysis from '{user_features_path}'...")

    # --- 1. Load and Validate Data ---
    input_file = Path(user_features_path)
    if not input_file.exists():
        print(f"Error: {user_features_path} not found. Please run build_features.py first.")
        return

    user_features_df = pd.read_csv(input_file, index_col='user_id')
    data = user_features_df.values.astype(float)
    
    print(f"Loaded feature matrix for {data.shape[0]} users with {data.shape[1]} features each.")

    if len(np.unique(data, axis=0)) == 1:
        print("\nWARNING: All users in the dataset have the exact same anomaly pattern.")
        print("The SOM cannot find outliers if there is no variation in the data.")
        return

    # --- 2. Implement the Multi-Epoch Training Strategy ---
    num_epochs = 10
    all_outliers = []
    
    print(f"\nRunning {num_epochs} independent training epochs to find consistent outliers...")

    num_users = data.shape[0]
    map_size = int(np.ceil(np.sqrt(5 * np.sqrt(num_users))))
    map_x, map_y = map_size, map_size
    print(f"Dynamically set map size to {map_x}x{map_y} for {num_users} users.")

    for epoch in range(num_epochs):
        print(f"\r--- Epoch {epoch + 1}/{num_epochs} ---", end="")
        
        som = MiniSom(map_x, map_y, data.shape[1],
                      sigma=1.5, learning_rate=0.5,
                      random_seed=np.random.randint(1000))

        som.random_weights_init(data)
        
        iterations = max(500, num_users * 5)
        som.train_random(data, iterations, verbose=False)
        
        # --- NEW & IMPROVED OUTLIER DETECTION LOGIC ---
        # Calculate quantization error for each user. This is the distance between
        # each user's data vector and its Best Matching Unit (BMU) on the map.
        # A high error means the user is far from any representative neuron (cluster).
        q_errors = np.linalg.norm(som.quantization(data) - data, axis=1)

        # Identify outliers based on the distribution of these errors.
        # Anyone in the top 5% (95th percentile) of errors is a candidate.
        error_threshold = np.percentile(q_errors, 95)
        
        # Get the indices of the users who are above the threshold
        outlier_indices = np.where(q_errors > error_threshold)[0]
        
        # Add the corresponding user_ids to our list
        for idx in outlier_indices:
            all_outliers.append(user_features_df.index[idx])
    
    print("\n--- Multi-Epoch Analysis Complete ---")

    # --- 3. Report Consistent Outliers ---
    if not all_outliers:
        print("No significant outliers were found across any of the training epochs.")
        return

    outlier_counts = Counter(all_outliers)
    sorted_outliers = sorted(outlier_counts.items(), key=lambda item: item[1], reverse=True)

    print("\nTop potential outliers (ranked by consistency across epochs):")
    strong_outlier_threshold = num_epochs // 2
    found_strong_outlier = False

    for user, count in sorted_outliers:
        if count >= strong_outlier_threshold:
            print(f"  -> User: {user:<20} (Flagged in {count}/{num_epochs} epochs) [STRONG CANDIDATE]")
            found_strong_outlier = True
        else:
            print(f"  -> User: {user:<20} (Flagged in {count}/{num_epochs} epochs) [Weak Candidate]")

    if not found_strong_outlier:
        print("\nNo users were consistently identified as strong outliers.")
        
    # --- 4. Visualize the U-Matrix of the LAST Epoch for reference ---
    plt.figure(figsize=(12, 12))
    plt.pcolor(som.distance_map().T, cmap='viridis')
    plt.colorbar(label='Inter-neuron Distance')
    plt.title(f'SOM U-Matrix (from last epoch, epoch {num_epochs})')
    plt.xlabel('SOM X-coordinate')
    plt.ylabel('SOM Y-coordinate')
    plt.savefig(output_image_path)
    print(f"\n✅ U-matrix visualization from the last epoch saved to '{output_image_path}'")
    plt.close()

if __name__ == "__main__":
    run_som_analysis()

