import pandas as pd
import json
import numpy as np
from pathlib import Path

def generate_anomaly_features(sessionized_events_path='data/normalized/events_sessionized.jsonl', output_path='user_features.csv'):
    """
    Reads sessionized event data, applies various sophisticated anomaly detection rules,
    and generates a user-feature matrix suitable for machine learning.
    """
    print(f"Starting ENHANCED anomaly feature generation from '{sessionized_events_path}'...")
    
    # --- 1. Load and Preprocess Data ---
    input_file = Path(sessionized_events_path)
    if not input_file.exists():
        print(f"Error: Input file not found at '{sessionized_events_path}'")
        return

    events = []
    with open(input_file, 'r') as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Warning: Skipping malformed JSON line: {line.strip()}")

    if not events:
        print("Error: No events were loaded from the file. Exiting.")
        return

    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.fillna({'process': '', 'resource': '', 'status': '', 'host': ''}, inplace=True)
    
    print(f"Loaded {len(df)} events.")

    # --- 2. Define ENHANCED Anomaly Logic ---
    all_users = df['user_id'].unique()
    feature_matrix = pd.DataFrame(index=all_users)
    print(f"Found {len(all_users)} unique users. Building feature matrix...")

    # --- Existing Anomaly Rules (Kept for baseline) ---
    abnormal_hours_df = df[(df['event_type'] == 'auth') & (df['status'] == 'success') & ((df['timestamp'].dt.hour > 20) | (df['timestamp'].dt.hour < 6))]
    users_abnormal_hours = abnormal_hours_df['user_id'].unique()
    feature_matrix['anomaly_login_abnormal_hours'] = feature_matrix.index.isin(users_abnormal_hours).astype(int)

    failed_logins_df = df[df['status'] == 'failure']
    failure_counts = failed_logins_df.groupby('user_id').size()
    users_high_failures = failure_counts[failure_counts > 5].index.tolist()
    feature_matrix['anomaly_exceeded_failed_logins'] = feature_matrix.index.isin(users_high_failures).astype(int)
    
    # --- NEW Anomaly Rules for Better Differentiation ---

    # Anomaly 8: First-time access to a host (Lateral Movement Indicator)
    successful_logins = df[(df['event_type'] == 'auth') & (df['status'] == 'success') & (df['host'] != '')].copy()
    # Find the first login time for each user-host pair
    first_login_times = successful_logins.loc[successful_logins.groupby(['user_id', 'host'])['timestamp'].idxmin()]
    # Now, for each user, find their very first login time across all hosts
    user_first_ever_login = first_login_times.loc[first_login_times.groupby('user_id')['timestamp'].idxmin()]
    # An event is a "first host access" if it's not the user's very first login ever
    first_host_access_df = pd.merge(first_login_times, user_first_ever_login[['user_id', 'timestamp']], on='user_id', suffixes=('', '_first_ever'))
    users_first_host_access = first_host_access_df[first_host_access_df['timestamp'] > first_host_access_df['timestamp_first_ever']]['user_id'].unique()
    feature_matrix['anomaly_first_time_host_access'] = feature_matrix.index.isin(users_first_host_access).astype(int)
    
    # Anomaly 9: Abnormal number of events in a session (Frequency Anomaly)
    events_per_session = df.groupby(['user_id', 'session_id']).size().reset_index(name='event_count')
    # Calculate the average session size for each user
    avg_session_size = events_per_session.groupby('user_id')['event_count'].mean()
    # Find sessions that are much larger than the user's average (e.g., 3 standard deviations)
    merged_df = pd.merge(events_per_session, avg_session_size.rename('avg_count'), on='user_id')
    std_dev_session_size = events_per_session.groupby('user_id')['event_count'].std().fillna(1)
    merged_df = pd.merge(merged_df, std_dev_session_size.rename('std_dev_count'), on='user_id')
    # A session is abnormal if its count is > avg + 3 * std_dev
    abnormal_sessions = merged_df[merged_df['event_count'] > (merged_df['avg_count'] + 3 * merged_df['std_dev_count'])]
    users_abnormal_session_size = abnormal_sessions['user_id'].unique()
    feature_matrix['anomaly_abnormal_session_size'] = feature_matrix.index.isin(users_abnormal_session_size).astype(int)

    # Anomaly 10: High number of unique sensitive files accessed
    sensitive_files_pattern = 'secrets.txt|config.json|/etc/shadow|/etc/passwd|credentials'
    sensitive_access = df[df['resource'].str.contains(sensitive_files_pattern, case=False, na=False)]
    unique_sensitive_files_count = sensitive_access.groupby('user_id')['resource'].nunique()
    users_many_sensitive_files = unique_sensitive_files_count[unique_sensitive_files_count > 2].index.tolist() # Threshold > 2 unique files
    feature_matrix['anomaly_many_sensitive_files'] = feature_matrix.index.isin(users_many_sensitive_files).astype(int)

    # --- 3. Inject a "Sanity Check" Outlier User ---
    # This proves the SOM can find an outlier if one exists.
    # This user has a unique pattern (only first_time_host_access and many_sensitive_files)
    # that should make it stand out from the rest of the population.
    test_user_id = 'test_outlier_user'
    if test_user_id not in feature_matrix.index:
        feature_matrix.loc[test_user_id] = 0 # Add new row with all zeros
        feature_matrix.at[test_user_id, 'anomaly_first_time_host_access'] = 1
        feature_matrix.at[test_user_id, 'anomaly_many_sensitive_files'] = 1
        print(f"\nInjected '{test_user_id}' for system validation.")

    # --- 4. Save the Feature Matrix ---
    feature_matrix.to_csv(output_path, index_label='user_id')
    print("-" * 50)
    print(f"✅ ENHANCED anomaly feature matrix saved to '{output_path}'")
    print(f"Matrix dimensions: {feature_matrix.shape[0]} users, {feature_matrix.shape[1]} anomaly features.")
    print("Sample of the generated data:")
    print(feature_matrix.head())
    print("-" * 50)

if __name__ == "__main__":
    generate_anomaly_features(
        sessionized_events_path='data/normalized/events_sessionized.jsonl',
        output_path='user_features.csv'
    )

