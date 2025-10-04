#!/usr/bin/env python3
import pandas as pd
import uuid

def main(infile="data/normalized/events.jsonl", outfile="data/normalized/events_sessionized.jsonl"):
  
    df = pd.read_json(infile, lines=True)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.sort_values(by=['user_id', 'timestamp'], inplace=True)
    
    time_diff = df.groupby('user_id')['timestamp'].diff().dt.total_seconds()
    
    session_change = (time_diff > 1800).cumsum()
    
    session_groups = df.groupby(['user_id', session_change])
    df['session_id'] = session_groups.ngroup().astype(str)
    
    df.to_json(outfile, orient='records', lines=True, date_format='iso')
    print(f"Sessionized {len(df)} events into '{outfile}'")
    print(f"Found {df['session_id'].nunique()} unique sessions.")

if __name__ == "__main__":
    main()