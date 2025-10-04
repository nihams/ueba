
import pandas as pd
from collections import defaultdict
import json
from pathlib import Path

def get_simple_action(event):
    if event['event_type'] == 'process' and pd.notna(event['process']):
        return f"process_execute_{event['process']}"
    return f"{event['event_type']}_{event['action']}"

def main():
    SCRIPT_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = SCRIPT_DIR.parent
    
    data_file = PROJECT_ROOT / "data" / "normalized" / "events_sessionized.jsonl"
    peer_group_file = PROJECT_ROOT / "user_to_peer_group.json"
    outfile = SCRIPT_DIR / "markov_models_by_group_2nd_order.json"

    df = pd.read_json(data_file, lines=True)
    
    with open(peer_group_file, 'r') as f:
        user_to_group = json.load(f)
        
    df['peer_group'] = df['user_id'].map(user_to_group)
    df.dropna(subset=['peer_group'], inplace=True)
    df['peer_group'] = df['peer_group'].astype(int)
    
    df['simple_action'] = df.apply(get_simple_action, axis=1)
    
    all_models = {}
    
    for group_id, group_df in df.groupby('peer_group'):
        print(f"Building 2nd-order model for Peer Group {group_id}...")
        transitions = defaultdict(lambda: defaultdict(int))
        
        for _, session in group_df.groupby('session_id'):
            actions = session.sort_values(by='timestamp')['simple_action'].tolist()
            if len(actions) < 3:
                continue
            for i in range(len(actions) - 2):
                state = tuple(actions[i:i+2])
                next_state = actions[i+2]
                transitions[str(state)][next_state] += 1
        
        for state, next_states in transitions.items():
            total = sum(next_states.values())
            for next_state in next_states:
                transitions[state][next_state] /= total
        
        all_models[str(group_id)] = transitions

    with open(outfile, 'w') as f:
        json.dump(all_models, f, indent=2)
        
    print(f"\nSuccessfully built 2nd-order models and saved to '{outfile}'")

if __name__ == "__main__":
    main()