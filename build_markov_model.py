#!/usr/bin/env python3
import pandas as pd
from collections import defaultdict
import json

def get_simple_action(event):
    """Creates a more descriptive action string for each event."""
    if event['event_type'] == 'process':
        return f"process_{event['action']}_{event['process']}"
    return f"{event['event_type']}_{event['action']}"

def main(infile="data/normalized/events_sessionized.jsonl", outfile="markov_model.json"):
    """
    Builds a Markov Chain model from session data and saves it to a file.
    The model is a dictionary of state transition probabilities.
    """
    df = pd.read_json(infile, lines=True)
    df['simple_action'] = df.apply(get_simple_action, axis=1)
    
    transitions = defaultdict(lambda: defaultdict(int))
    
    # Group by session and count all the transitions
    for _, session in df.groupby('session_id'):
        actions = session.sort_values(by='timestamp')['simple_action'].tolist()
        for i in range(len(actions) - 1):
            transitions[actions[i]][actions[i+1]] += 1
            
    # Convert the counts into probabilities
    for state, next_states in transitions.items():
        total_transitions = sum(next_states.values())
        for next_state in next_states:
            transitions[state][next_state] /= total_transitions
            
    with open(outfile, 'w') as f:
        json.dump(transitions, f, indent=2)
        
    print(f"Markov model built with {len(transitions)} states and saved to '{outfile}'")

if __name__ == "__main__":
    main()