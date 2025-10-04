import pandas as pd
import json
from datetime import datetime
import math 

PROFILE_DB = 'user_profiles.json'


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (int, float)) and (math.isnan(obj) or math.isinf(obj)):
            return None 
        if pd.isna(obj):
            return None 
        return super().default(obj)

def load_profiles():
    try:
        with open(PROFILE_DB, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_profiles(profiles):
    with open(PROFILE_DB, 'w') as f:
        json.dump(profiles, f, indent=2, cls=CustomEncoder)

def get_or_create_profile(profiles, user_id):
    if user_id not in profiles:
        profiles[user_id] = {
            "user_id": user_id,
            "known_ips": [], "known_hosts": [], "typical_active_hours": [],
            "process_whitelist": [],
            "failed_login_rate": {"count": 0, "first_event_time": None, "rate_per_hour": 0.0},
            "last_seen": None,
            "risk_score": 0
        }
    return profiles[user_id]

def run_analysis():
    alert_weights = {
        "New IP": 5,
        "New Host": 10,
        "Peer Group Deviation": 25,
        "Suspicious Sequence": 50
    }

    print("Loading and preparing sessionized data...")
    try:
        df = pd.read_json('data/normalized/events_sessionized.jsonl', lines=True)
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df.dropna(subset=['timestamp'], inplace=True)
        df = df.sort_values(by='timestamp')
    except FileNotFoundError:
        print("Error: 'data/normalized/events_sessionized.jsonl' not found. Please run sessionize_events.py first.")
        return

    print("Loading profiles and peer group data...")
    profiles = load_profiles()
    try:
        with open('user_to_peer_group.json', 'r') as f:
            user_to_group = json.load(f)
    except FileNotFoundError:
        print("Warning: 'user_to_peer_group.json' not found. Skipping peer group analysis.")
        user_to_group = {}

    for user_id, profile in profiles.items():
        profile['risk_score'] = round(profile.get('risk_score', 0) * 0.99)

    alerts = []
    group_profiles = {i: {'known_hosts': set()} for i in set(user_to_group.values())}
    
    session_tracker = {}

    print("\nProcessing events and applying all detection logic...")
    for index, event in df.iterrows():
        user_id = event.get('user_id')
        if pd.isna(user_id):
            continue

        profile = get_or_create_profile(profiles, user_id)
        
        # Rule 1: New IP
        event_ip = event.get('src_ip')
        if pd.notna(event_ip) and event_ip not in profile['known_ips']:
            alerts.append({"alert_type": "New IP", "user_id": user_id, "details": f"New IP {event_ip}"})
            profile['risk_score'] += alert_weights["New IP"] # Add to risk score
            profile['known_ips'].append(event_ip)

        # Rule 2: New Host
        event_host = event.get('host')
        if pd.notna(event_host) and event_host not in profile['known_hosts']:
            alerts.append({"alert_type": "New Host", "user_id": user_id, "details": f"Accessed new host {event_host}"})
            profile['risk_score'] += alert_weights["New Host"] # Add to risk score
            profile['known_hosts'].append(event_host)
            
        # Rule 3: Peer Group Deviation
        peer_group_id = user_to_group.get(user_id)
        if peer_group_id is not None and pd.notna(event_host):
            group_known_hosts = group_profiles[peer_group_id]['known_hosts']
            if event_host not in group_known_hosts and len(group_known_hosts) > 5:
                alerts.append({"alert_type": "Peer Group Deviation", "user_id": user_id, "details": f"Accessed unusual host '{event_host}' for peer group {peer_group_id}."})
                profile['risk_score'] += alert_weights["Peer Group Deviation"] # Add to risk score
            group_known_hosts.add(event_host)
            
        # Rule 4: Suspicious Sequence
        session_id = event.get('session_id')
        action = event.get('action')
        status = event.get('status')
        if pd.notna(session_id) and pd.notna(action):
            last_action_status = session_tracker.get(session_id)
            if last_action_status == 'login_failure' and action == 'login' and status == 'success':
                alerts.append({"alert_type": "Suspicious Sequence", "user_id": user_id, "details": "Successful login followed a failed login in the same session."})
                profile['risk_score'] += alert_weights["Suspicious Sequence"] # Add to risk score
            session_tracker[session_id] = f"{action}_{status}"

        if pd.notna(event['timestamp']):
            profile['last_seen'] = event['timestamp'].isoformat()

    print("\nSaving updated user profiles with new risk scores...")
    save_profiles(profiles)
    print(f"\nGenerated {len(alerts)} alerts.")
    with open('alerts.json', 'w') as f:
        json.dump(alerts, f, indent=2, cls=CustomEncoder)
    print("New alerts saved to alerts.json")

if __name__ == "__main__":
    run_analysis()