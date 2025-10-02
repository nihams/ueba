import pandas as pd
import uuid

def create_sessions(timeout_minutes=30):
    """
    Reads normalized events and groups them into sessions based on user activity.
    """
    print("Loading normalized events...")
    try:
        df = pd.read_json('data/normalized/events.jsonl', lines=True)
    except FileNotFoundError:
        print("Error: 'data/normalized/events.jsonl' not found.")
        return

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.dropna(subset=['timestamp', 'user_id'], inplace=True)

    # Sort by user and time to process events in order
    df = df.sort_values(by=['user_id', 'timestamp'])

    print("Assigning session IDs to events...")
    
    # Calculate the time difference between consecutive events for each user
    df['time_diff'] = df.groupby('user_id')['timestamp'].diff()

    # A new session starts if the time difference is greater than our timeout
    # or if the user ID changes (which is handled by the groupby)
    timeout_delta = pd.Timedelta(minutes=timeout_minutes)
    df['new_session'] = (df['time_diff'] > timeout_delta) | (df['time_diff'].isnull())

    # Assign a unique session ID to each session
    df['session_id'] = (df['new_session'].cumsum())
    
    # Optional: Convert session_id to a more unique identifier like UUID
    session_map = {i: str(uuid.uuid4()) for i in df['session_id'].unique()}
    df['session_id'] = df['session_id'].map(session_map)

    # Drop helper columns
    df = df.drop(columns=['time_diff', 'new_session'])

    output_path = 'data/normalized/events_sessionized.jsonl'
    df.to_json(output_path, orient='records', lines=True, date_format='iso')

    print(f"Successfully created sessions for {df['session_id'].nunique()} sessions.")
    print(f"Saved sessionized data to {output_path}")
    print("\nExample of sessionized data:")
    print(df[['timestamp', 'user_id', 'action', 'session_id']].head())

if __name__ == "__main__":
    create_sessions()