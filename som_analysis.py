import pandas as pd
import numpy as np
from minisom import MiniSom
import matplotlib.pyplot as plt
from pathlib import Path
from collections import Counter
import json

def run_som_analysis(user_features_path='user_features.csv', output_image_path='som_u_matrix.png', results_path='som_results.json'):
    """
    Performs an advanced SOM analysis using quantization error and a multi-epoch 
    strategy to robustly identify outliers and saves the results for the dashboard.
    """
    print(f"Starting Advanced SOM analysis from '{user_features_path}'...")

    # --- 1. Load and Validate Data ---
    input_file = Path(user_features_path)
    if not input_file.exists():
        print(f"Error: {user_features_path} not found. Please run build_features.py first.")
        return

    user_features_df = pd.read_csv(input_file, index_col='user_id')
    
    # Exclude score columns from the data used for SOM training
    feature_cols = [col for col in user_features_df.columns if not col.endswith('_score')]
    data = user_features_df[feature_cols].values.astype(float)
    
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
        
        q_errors = np.linalg.norm(som.quantization(data) - data, axis=1)
        error_threshold = np.percentile(q_errors, 95)
        outlier_indices = np.where(q_errors > error_threshold)[0]
        
        for idx in outlier_indices:
            all_outliers.append(user_features_df.index[idx])
    
    print("\n--- Multi-Epoch Analysis Complete ---")

    # --- 3. Report and Save Consistent Outliers ---
    sorted_outliers = []
    if all_outliers:
        outlier_counts = Counter(all_outliers)
        sorted_outliers_tuples = sorted(outlier_counts.items(), key=lambda item: item[1], reverse=True)
        
        print("\nTop potential outliers (ranked by consistency across epochs):")
        strong_outlier_threshold = num_epochs // 2

        for user, count in sorted_outliers_tuples:
            user_data = user_features_df.loc[user]
            result_entry = {
                "user_id": user,
                "flagged_epochs": count,
                "total_epochs": num_epochs,
                "attack_score": int(user_data.get('attack_score', 0)),
                "benign_score": int(user_data.get('benign_score', 0))
            }
            sorted_outliers.append(result_entry)

            if count >= strong_outlier_threshold:
                print(f"  -> User: {user:<20} (Flagged in {count}/{num_epochs} epochs) [STRONG CANDIDATE]")
            else:
                print(f"  -> User: {user:<20} (Flagged in {count}/{num_epochs} epochs) [Weak Candidate]")
    else:
        print("No significant outliers were found across any of the training epochs.")

    # Save the ranked results to a JSON file for the dashboard
    with open(results_path, 'w') as f:
        json.dump(sorted_outliers, f, indent=2)
    print(f"\n✅ SOM analysis results saved to '{results_path}'")
        
    # --- 4. Visualize the U-Matrix of the LAST Epoch for reference ---
    plt.figure(figsize=(12, 12))
    plt.pcolor(som.distance_map().T, cmap='viridis')
    plt.colorbar(label='Inter-neuron Distance')
    plt.title(f'SOM U-Matrix (from last epoch, epoch {num_epochs})')
    plt.xlabel('SOM X-coordinate')
    plt.ylabel('SOM Y-coordinate')
    plt.savefig(output_image_path)
    print(f"✅ U-matrix visualization from the last epoch saved to '{output_image_path}'")
    plt.close()

if __name__ == "__main__":
    run_som_analysis()

