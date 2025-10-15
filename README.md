# Project Drishti - UEBA Dashboard

**See the Unseen, Detect the Undetected**

Project Drishti is an advanced User and Entity Behavior Analytics (UEBA) dashboard for monitoring, analyzing, and visualizing user risk and anomaly patterns in enterprise environments. It integrates Markov models, Self-Organizing Maps (SOM), and MITRE ATT&CK mapping to provide comprehensive insights into user behavior and security risks.

---

## Features

- **Unified User Risk Overview:** Displays top high-risk users with composite scores, risk levels, Markov/SOM risk, and anomaly details.
- **Strategic Anomaly Map (SOM):** Interactive visualization of user behavior clusters and outliers.
- **MITRE ATT&CK Mapper:** Maps detected techniques to MITRE ATT&CK framework for tactical analysis.
- **Deep Dive Analysis:** Detailed breakdown of individual user risk, anomaly scores, contributing alerts, and behavioral sequences.
- **Interactive UI:** Select users from sidebar or click on SOM map for instant analysis and highlighting.
- **Markov Model Integration:** Sequence anomaly scoring and peer group analysis.
- **Data Pipeline:** Scripts for feature engineering, normalization, sessionization, and log generation.

---

## Folder Structure

```
alerts.json
analysis_pipeline.py
app.py
assign_peer_groups.py
build_features.py
generate_logs.py
normalize.py
sequence_anomalies_2nd_order.jsonl
sequence_anomalies.jsonl
sessionize_events.py
som_analysis.py
som_results.json
user_features.csv
user_profiles.json
user_to_peer_group.json

data/
    mock_sequence_alerts.json
    mock_unified_risk.json
    mock_user_anomaly_patterns.jsonl
    normalized/
        events_sessionized.jsonl
        events.jsonl
    raw/
        endpoint_proc.jsonl
        file_audit.csv
        web_proxy.jsonl

markov-model/
    build_markov_model.py
    markov_models_by_group_2nd_order.json
    score_sequences.py

pyattck/
    (MITRE ATT&CK integration library and scripts)
    Mitre_mapper/
        mapper.py
        mitre_detection_report.json
        test_mitre.py
        ueba_integration.py
    Pyattck Library/
        (core library files)
    tests/
        (unit tests)
    docs/
        (documentation)
```

---

## Main Components

- [`app.py`](app.py): Streamlit dashboard application.
- [`data/`](data): Contains mock and processed data files for testing and analysis.
- [`markov-model/`](markov-model): Scripts and models for Markov-based sequence analysis.
- [`pyattck/`](pyattck): MITRE ATT&CK integration, mapping, and supporting library.
- Other Python scripts: Data processing, feature engineering, normalization, and analysis.

---

## Getting Started

### Prerequisites

- Python 3.8+
- [Streamlit](https://streamlit.io/)
- pandas, numpy, plotly

Install dependencies:

```sh
pip install -r requirements.txt
```

### Running the Dashboard

Start the Streamlit app:

```sh
streamlit run app.py
```

The dashboard will open in your browser. You can interactively explore user risk, anomaly patterns, and MITRE ATT&CK mappings.

---

## Data Sources

- **Mock Data:** Provided in [`data/`](data) for demonstration and testing.
- **MITRE Detection Report:** Simulated in session state for dashboard analysis.
- **Markov & SOM Models:** Scripts and results in [`markov-model/`](markov-model) and [`som_analysis.py`](som_analysis.py).

---

## Customization

- To use real data, replace mock files in [`data/`](data) and update the loading functions in [`app.py`](app.py).
- Extend analysis by modifying or adding scripts for new features or models.
- MITRE ATT&CK mapping and integration can be customized via [`pyattck/`](pyattck).

---

## License

See [`LICENSE.md`](pyattck/LICENSE.md) for details.

---

**Project Drishti v2.0** | Real-time Behavioral Risk Monitoring | Professional UEBA Dashboard
