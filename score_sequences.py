#!/usr/bin/env python3
import pandas as pd
import json
import math

def get_simple_action(event):
    """Creates a more descriptive action string for each event."""
    if event['event_type'] == 'process':
        return f"process_{event['action']}_{event['process']}"
    return f"{event['event_type']}_{event['action']}"

def main(data_file="data/normalized/events_sessionized.jsonl", model_file="markov_model.json"):
    """
    Loads a pre-trained Markov model and scores all user sessions to find
    the most anomalous sequences.
    """
    with open(model_file, 'r') as f:
        model = json.load(f)
    
    df = pd.read_json(data_file, lines=True)
    df['simple_action'] = df.apply(get_simple_action, axis=1)
    
    session_scores = {}
    for session_id, session in df.groupby('session_id'):
        actions = session.sort_values(by='timestamp')['simple_action'].tolist()
        log_probability = 0
        transition_count = 0
        
        for i in range(len(actions) - 1):
            from_state = actions[i]
            to_state = actions[i+1]
            
            # Use a small floor probability for transitions never seen before
            prob = model.get(from_state, {}).get(to_state, 1e-9) 
            log_probability += -math.log(prob)
            transition_count += 1
            
        # Normalize score by sequence length to avoid unfairly penalizing long, normal sessions
        score = log_probability / transition_count if transition_count > 0 else 0
        
        session_scores[session_id] = {
            "user_id": session['user_id'].iloc[0],
            "score": score,
            "sequence": " -> ".join(actions)
        }
        
    results_df = pd.DataFrame.from_dict(session_scores, orient='index')
    results_df.sort_values(by='score', ascending=False, inplace=True)
    
    print("\n--- Top 10 Most Anomalous Sequences ---")
    print(results_df.head(10))
    
    # Save results for the dashboard
    results_df.to_json("sequence_anomalies.jsonl", orient='records', lines=True)
    print("\nFull sequence analysis results saved to 'sequence_anomalies.jsonl'")

if __name__ == "__main__":
    main()