import pandas as pd
import numpy as np

def engineer_features():
    """
    Reads normalized event data and engineers a feature set for each user.
    """
    print("Loading normalized events...")
    try:
        df = pd.read_json('data/normalized/events.jsonl', lines=True)
    except FileNotFoundError:
        print("Error: 'data/normalized/events.jsonl' not found.")
        return

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.dropna(subset=['timestamp', 'user_id'], inplace=True)
    
    print("Engineering features for each user...")

    # 1. Diversity Features (unique hosts and IPs)
    diversity_features = df.groupby('user_id').agg(
        host_diversity=('host', 'nunique'),
        ip_diversity=('src_ip', 'nunique')
    ).reset_index()

    # 2. Activity Timing Features (off-hours ratio)
    # Define off-hours as before 9 AM or after 5 PM (17:00)
    df['is_off_hours'] = (df['timestamp'].dt.hour < 9) | (df['timestamp'].dt.hour > 17)
    timing_features = df.groupby('user_id')['is_off_hours'].mean().reset_index()
    timing_features.rename(columns={'is_off_hours': 'off_hours_ratio'}, inplace=True)

    # 3. Frequency Features (logins per day)
    # Get the time range of activity for each user
    time_range = df.groupby('user_id')['timestamp'].agg(['min', 'max'])
    # Calculate days active, add 1 to avoid division by zero
    time_range['days_active'] = (time_range['max'] - time_range['min']).dt.days + 1
    
    login_counts = df.groupby('user_id').size().reset_index(name='total_logins')
    
    frequency_features = pd.merge(login_counts, time_range, on='user_id')
    frequency_features['logins_per_day'] = frequency_features['total_logins'] / frequency_features['days_active']


    # --- Merge all features into one DataFrame ---
    print("Merging features...")
    features_df = pd.merge(diversity_features, timing_features, on='user_id')
    features_df = pd.merge(features_df, frequency_features[['user_id', 'logins_per_day']], on='user_id')
    
    # Fill any potential NaN values with 0
    features_df.fillna(0, inplace=True)
    
    # Save to CSV
    output_path = 'user_features.csv'
    features_df.to_csv(output_path, index=False)
    print(f"Successfully engineered features for {len(features_df)} users.")
    print(f"Saved to {output_path}")
    print("\nFeature examples:")
    print(features_df.head())


if __name__ == "__main__":
    engineer_features()