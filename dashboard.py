import streamlit as st
import pandas as pd
import json

st.set_page_config(layout="wide")
st.title("UEBA Risk Dashboard")

# Load the data
try:
    with open('user_profiles.json', 'r') as f:
        profiles = json.load(f)
    with open('alerts.json', 'r') as f:
        alerts = json.load(f)
except FileNotFoundError:
    st.error("Please run the analysis_pipeline.py first to generate profile and alert files.")
    st.stop()

# Convert profiles to a DataFrame for easy sorting and display
profiles_list = list(profiles.values())
if not profiles_list:
    st.warning("No user profiles found.")
    st.stop()
    
df_profiles = pd.DataFrame(profiles_list)
df_profiles = df_profiles.sort_values(by='risk_score', ascending=False)

st.header("Top Riskiest Users")
st.dataframe(df_profiles[['user_id', 'risk_score', 'last_seen']].head(10))

st.header("Detailed User Analysis")
selected_user = st.selectbox("Select a User", options=df_profiles['user_id'])

# Display selected user's profile
if selected_user:
    user_profile = profiles[selected_user]
    st.subheader(f"Profile for: {user_profile['user_id']}")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Current Risk Score", user_profile.get('risk_score', 0))
        st.write("**Known Hosts:**", user_profile['known_hosts'])
    with col2:
        st.write("**Last Seen:**", user_profile.get('last_seen', 'N/A'))
        st.write("**Known IPs:**", user_profile['known_ips'])

    # Display alerts for the selected user
    st.subheader("Recent Alerts")
    user_alerts = [alert for alert in alerts if alert['user_id'] == selected_user]
    if user_alerts:
        df_alerts = pd.DataFrame(user_alerts)
        st.dataframe(df_alerts)
    else:
        st.write("No alerts found for this user.")