import pandas as pd
import json
from pathlib import Path

<<<<<<< HEAD
def generate_hackathon_features(sessionized_events_path='data/normalized/events_sessionized.jsonl', output_path='user_features.csv'):
    """
    Reads enhanced sessionized data and applies a mix of high-impact and benign 
    anomaly detection rules to create a realistic feature matrix.
    """
    print(f"Starting HACKATHON feature generation from '{sessionized_events_path}'...")
=======
def generate_anomaly_features(sessionized_events_path='data/normalized/events_sessionized.jsonl', output_path='user_features.csv'):
    print(f"Starting ENHANCED anomaly feature generation from '{sessionized_events_path}'...")
>>>>>>> 22a2f47f0803f8ab08b449d7c6b26f9ce3342f06
    
    input_file = Path(sessionized_events_path)
    if not input_file.exists():
        print(f"Error: Input file not found at '{sessionized_events_path}'")
        return

    df = pd.read_json(input_file, lines=True, dtype=False)
    
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.fillna({
        'process': '', 'resource': '', 'status': '', 'host': '',
        'user_agent': '', 'dst_hostname': '', 'bytes_out': 0, 'src_ip': ''
    }, inplace=True)
    
    print(f"Loaded {len(df)} sessionized events.")

    all_users = df['user_id'].unique()
    feature_matrix = pd.DataFrame(index=all_users)
    print(f"Found {len(all_users)} unique users. Building feature matrix...")

<<<<<<< HEAD
    # --- 2. Define High-Impact Anomaly Logic (Detects the Attacker) ---
    print("  - Applying high-impact, malicious-specific rules...")
    suspicious_ips = ['5.188.10.225']
    impossible_travel_df = df[(df['event_type'] == 'auth') & (df['status'] == 'success') & (df['src_ip'].isin(suspicious_ips))]
    feature_matrix['attack_impossible_travel'] = feature_matrix.index.isin(impossible_travel_df['user_id'].unique()).astype(int)

    abnormal_ua_df = df[(df['event_type'] == 'web') & (df['user_agent'].str.contains("PowerShell", na=False))]
    feature_matrix['attack_c2_beaconing_ua'] = feature_matrix.index.isin(abnormal_ua_df['user_id'].unique()).astype(int)

    large_upload_df = df[(df['event_type'] == 'web') & (df['http_method'] == 'POST') & (df['bytes_out'] > 1 * 1024 * 1024) & (df['url_category'].isin(['File Sharing', 'Text & Media Sharing']))]
    feature_matrix['attack_data_exfiltration'] = feature_matrix.index.isin(large_upload_df['user_id'].unique()).astype(int)

    sensitive_file_df = df[(df['event_type'] == 'file') & (df['resource'].str.contains("project_x_blueprints.pdf", na=False))]
    feature_matrix['attack_sensitive_file_access'] = feature_matrix.index.isin(sensitive_file_df['user_id'].unique()).astype(int)

    admin_discovery_df = df[(df['event_type'] == 'process') & (df['raw'].str.contains('net group "Domain Admins"', na=False))]
    feature_matrix['attack_admin_discovery'] = feature_matrix.index.isin(admin_discovery_df['user_id'].unique()).astype(int)

    # --- 3. Define Benign Anomaly Logic (Creates Realistic Noise) ---
    print("  - Applying benign anomaly rules to simulate real-world noise...")

    # Benign Anomaly 1: First time host access (Admins do this normally)
    successful_logins = df[(df['event_type'] == 'auth') & (df['status'] == 'success') & (df['host'] != '')].copy()
    first_login_times = successful_logins.loc[successful_logins.groupby(['user_id', 'host'])['timestamp'].idxmin()]
=======
    abnormal_hours_df = df[(df['event_type'] == 'auth') & (df['status'] == 'success') & ((df['timestamp'].dt.hour > 20) | (df['timestamp'].dt.hour < 6))]
    users_abnormal_hours = abnormal_hours_df['user_id'].unique()
    feature_matrix['anomaly_login_abnormal_hours'] = feature_matrix.index.isin(users_abnormal_hours).astype(int)

    failed_logins_df = df[df['status'] == 'failure']
    failure_counts = failed_logins_df.groupby('user_id').size()
    users_high_failures = failure_counts[failure_counts > 5].index.tolist()
    feature_matrix['anomaly_exceeded_failed_logins'] = feature_matrix.index.isin(users_high_failures).astype(int)

    successful_logins = df[(df['event_type'] == 'auth') & (df['status'] == 'success') & (df['host'] != '')].copy()

    first_login_times = successful_logins.loc[successful_logins.groupby(['user_id', 'host'])['timestamp'].idxmin()]
    
    #find first login time across all hosts for each
>>>>>>> 22a2f47f0803f8ab08b449d7c6b26f9ce3342f06
    user_first_ever_login = first_login_times.loc[first_login_times.groupby('user_id')['timestamp'].idxmin()]
    first_host_access_df = pd.merge(first_login_times, user_first_ever_login[['user_id', 'timestamp']], on='user_id', suffixes=('', '_first_ever'))
    users_first_host_access = first_host_access_df[first_host_access_df['timestamp'] > first_host_access_df['timestamp_first_ever']]['user_id'].unique()
    feature_matrix['benign_first_time_host_access'] = feature_matrix.index.isin(users_first_host_access).astype(int)

    # Benign Anomaly 2: Large Git Push (Developers do this normally)
    large_git_push_df = df[(df['event_type'] == 'web') & (df['http_method'] == 'POST') & (df['bytes_out'] > 500 * 1024) & (df['dst_hostname'] == 'github.com')]
    users_large_git_push = large_git_push_df['user_id'].unique()
    feature_matrix['benign_large_git_push'] = feature_matrix.index.isin(users_large_git_push).astype(int)
    
<<<<<<< HEAD
    # Benign Anomaly 3: Command-line web access (Developers do this normally)
    cli_web_df = df[(df['event_type'] == 'web') & (df['user_agent'].str.contains("curl|wget", na=False, case=False))]
    users_cli_web = cli_web_df['user_id'].unique()
    feature_matrix['benign_cli_web_access'] = feature_matrix.index.isin(users_cli_web).astype(int)
    
    # --- NEW BENIGN RULES TO ADD MORE NOISE ---

    # Benign Anomaly 4: Multiple Failed Logins (Common user error)
    failed_logins_df = df[df['status'] == 'failure']
    failure_counts = failed_logins_df.groupby('user_id').size()
    # Flag any user with more than 3 failed logins in the whole period.
    users_with_failures = failure_counts[failure_counts > 3].index.tolist()
    feature_matrix['benign_multiple_failed_logins'] = feature_matrix.index.isin(users_with_failures).astype(int)

    # Benign Anomaly 5: High Volume of Web Browsing (Could be research or non-work activity)
    web_gets = df[(df['event_type'] == 'web') & (df['http_method'] == 'GET')].copy()
    web_gets['day'] = web_gets['timestamp'].dt.date
    daily_get_counts = web_gets.groupby(['user_id', 'day']).size().reset_index(name='count')
    # Anything in the top 10% of daily activity is considered "high volume".
    high_volume_threshold = daily_get_counts['count'].quantile(0.90)
    high_volume_users = daily_get_counts[daily_get_counts['count'] > high_volume_threshold]['user_id'].unique()
    feature_matrix['benign_high_web_volume'] = feature_matrix.index.isin(high_volume_users).astype(int)
    
    # --- 4. Save the Feature Matrix ---
    feature_matrix.dropna(how='all', inplace=True)
    # Create separate scores for attack and benign anomalies for the dashboard
    attack_cols = [col for col in feature_matrix.columns if col.startswith('attack_')]
    benign_cols = [col for col in feature_matrix.columns if col.startswith('benign_')]
    
    feature_matrix['attack_score'] = feature_matrix[attack_cols].sum(axis=1)
    feature_matrix['benign_score'] = feature_matrix[benign_cols].sum(axis=1)
    
    # Sort by attack score first, then by benign score
    feature_matrix = feature_matrix.sort_values(by=['attack_score', 'benign_score'], ascending=False)
    
=======
    events_per_session = df.groupby(['user_id', 'session_id']).size().reset_index(name='event_count')
    avg_session_size = events_per_session.groupby('user_id')['event_count'].mean()
    merged_df = pd.merge(events_per_session, avg_session_size.rename('avg_count'), on='user_id')
    std_dev_session_size = events_per_session.groupby('user_id')['event_count'].std().fillna(1)
    merged_df = pd.merge(merged_df, std_dev_session_size.rename('std_dev_count'), on='user_id')
    #abnormal if its count is > avg + 3 * std_dev
    abnormal_sessions = merged_df[merged_df['event_count'] > (merged_df['avg_count'] + 3 * merged_df['std_dev_count'])]
    users_abnormal_session_size = abnormal_sessions['user_id'].unique()
    feature_matrix['anomaly_abnormal_session_size'] = feature_matrix.index.isin(users_abnormal_session_size).astype(int)

    sensitive_files_pattern = 'secrets.txt|config.json|/etc/shadow|/etc/passwd|credentials'
    sensitive_access = df[df['resource'].str.contains(sensitive_files_pattern, case=False, na=False)]
    unique_sensitive_files_count = sensitive_access.groupby('user_id')['resource'].nunique()
    users_many_sensitive_files = unique_sensitive_files_count[unique_sensitive_files_count > 2].index.tolist() # Threshold > 2 unique files
    feature_matrix['anomaly_many_sensitive_files'] = feature_matrix.index.isin(users_many_sensitive_files).astype(int)

    test_user_id = 'test_outlier_user'
    if test_user_id not in feature_matrix.index:
        feature_matrix.loc[test_user_id] = 0
        feature_matrix.at[test_user_id, 'anomaly_first_time_host_access'] = 1
        feature_matrix.at[test_user_id, 'anomaly_many_sensitive_files'] = 1
        print(f"\nInjected '{test_user_id}' for system validation.")

>>>>>>> 22a2f47f0803f8ab08b449d7c6b26f9ce3342f06
    feature_matrix.to_csv(output_path, index_label='user_id')

    print("-" * 50)
<<<<<<< HEAD
    print(f"✅ HACKATHON feature matrix saved to '{output_path}'")
    print(f"Matrix dimensions: {feature_matrix.shape[0]} users, {feature_matrix.shape[1]} features.")
    print("\nSample of the final, realistic data (top users by score):")
    print(feature_matrix.head(15))
=======
    print(f"ENHANCED anomaly feature matrix saved to '{output_path}'")
    print(f"Matrix dimensions: {feature_matrix.shape[0]} users, {feature_matrix.shape[1]} anomaly features.")
    print("Sample of the generated data:")
    print(feature_matrix.head())
>>>>>>> 22a2f47f0803f8ab08b449d7c6b26f9ce3342f06
    print("-" * 50)

if __name__ == "__main__":
    generate_hackathon_features()

