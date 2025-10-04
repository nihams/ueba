
import pandas as pd
import json
import math
from pathlib import Path

def get_simple_action(event):
    if event['event_type'] == 'process' and pd.notna(event['process']):
        return f"process_execute_{event['process']}"
    return f"{event['event_type']}_{event['action']}"

def main():
    SCRIPT_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = SCRIPT_DIR.parent
    
    data_file = PROJECT_ROOT / "data" / "normalized" / "events_sessionized.jsonl"
    models_file = SCRIPT_DIR / "markov_models_by_group_2nd_order.json"
    peer_group_file = PROJECT_ROOT / "user_to_peer_group.json"
    outfile = PROJECT_ROOT / "sequence_anomalies_2nd_order.jsonl"

    with open(models_file, 'r') as f:
        models = json.load(f)
        
    with open(peer_group_file, 'r') as f:
        user_to_group = json.load(f)

    df = pd.read_json(data_file, lines=True)
    df['simple_action'] = df.apply(get_simple_action, axis=1)
    df['peer_group'] = df['user_id'].map(user_to_group)
    
    session_scores = {}
    for session_id, session in df.groupby('session_id'):
        user = session['user_id'].iloc[0]
        group = str(session['peer_group'].iloc[0]) if pd.notna(session['peer_group'].iloc[0]) else None
        
        if not group or group not in models:
            continue
            
        model = models[group]
        actions = session.sort_values(by='timestamp')['simple_action'].tolist()
        log_probability = 0
        transition_count = 0
        
        if len(actions) < 3:
            continue
        
        for i in range(len(actions) - 2):
            state = str(tuple(actions[i:i+2]))
            next_state = actions[i+2]
            prob = model.get(state, {}).get(next_state, 1e-9)
            log_probability += -math.log(prob)
            transition_count += 1
            
        score = log_probability / transition_count if transition_count > 0 else 0
        
        session_scores[session_id] = {
            "user_id": user,
            "score": score,
            "sequence": " -> ".join(actions)
        }
        
    results_df = pd.DataFrame.from_dict(session_scores, orient='index')
    results_df.sort_values(by='score', ascending=False, inplace=True)
    
    print("\n--- Top 10 Most Anomalous Sequences (2nd-Order Peer Group Models) ---")
    print(results_df.head(10))
    
    results_df.to_json(outfile, orient='records', lines=True)
    print(f"\nFull 2nd-order sequence analysis results saved to '{outfile}'")

if __name__ == "__main__":
    main()