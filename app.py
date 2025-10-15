import streamlit as st
import pandas as pd
import json
import plotly.graph_objects as go
import numpy as np

# --- Helper Functions for Data Loading and Styling ---

@st.cache_data
def load_mitre_report(file_content):
    """
    Load the MITRE detection report from the JSON file content.
    Returns the raw list and a processed DataFrame of alerts.
    """
    try:
        data = json.loads(file_content)
        
        alerts_data = []
        for entry in data:
            user_id = entry.get('user_id', 'N/A')
            source = entry.get('source', 'N/A')
            for technique in entry.get('detected_techniques', []):
                alerts_data.append({
                    "User ID": user_id,
                    "Source": source,
                    "Technique ID": technique.get('id', 'N/A'),
                    "Technique Name": technique.get('name', 'N/A'),
                    "Confidence": f"{technique.get('confidence', 0.0) * 100:.0f}%",
                    "Rule Matched": technique.get('rule_matched', 'N/A'),
                    "Description": technique.get('description', 'N/A')
                })
        
        return data, pd.DataFrame(alerts_data)
    except Exception as e:
        st.error(f"Error loading MITRE report data: {str(e)}")
        return [], pd.DataFrame()

# NEW: Function to load data from the provided risk table image (Task 1)
@st.cache_data
def load_top_risky_users_data():
    """
    Load the actual Top 10 High Risk User data from the provided image/table.
    This data replaces the mock unified risk data.
    """
    data = [
        {"Rank": 1, "User ID": "dudleynicholas", "Composite Risk Score": 68.4, "Risk Level": "HIGH", "Markov Risk": 72.1, "SOM Risk": 62.5, "Suspicious Occurrences": 89, "Max Anomaly Score": 3.78},
        {"Rank": 2, "User ID": "jacqueline19", "Composite Risk Score": 66.8, "Risk Level": "HIGH", "Markov Risk": 69.3, "SOM Risk": 62.5, "Suspicious Occurrences": 84, "Max Anomaly Score": 3.74},
        {"Rank": 3, "User ID": "mitchellclark", "Composite Risk Score": 64.2, "Risk Level": "HIGH", "Markov Risk": 67.8, "SOM Risk": 58.4, "Suspicious Occurrences": 78, "Max Anomaly Score": 3.42},
        {"Rank": 4, "User ID": "xreid", "Composite Risk Score": 63.1, "Risk Level": "HIGH", "Markov Risk": 66.4, "SOM Risk": 57.6, "Suspicious Occurrences": 76, "Max Anomaly Score": 3.74},
        {"Rank": 5, "User ID": "hoffmanjennifer", "Composite Risk Score": 58.9, "Risk Level": "HIGH", "Markov Risk": 62.1, "SOM Risk": 53.2, "Suspicious Occurrences": 71, "Max Anomaly Score": 3.64},
        {"Rank": 6, "User ID": "susanrogers", "Composite Risk Score": 57.3, "Risk Level": "HIGH", "Markov Risk": 60.8, "SOM Risk": 51.0, "Suspicious Occurrences": 68, "Max Anomaly Score": 3.41},
        {"Rank": 7, "User ID": "robinsonwilliam", "Composite Risk Score": 56.7, "Risk Level": "HIGH", "Markov Risk": 59.5, "SOM Risk": 51.6, "Suspicious Occurrences": 66, "Max Anomaly Score": 3.17},
        {"Rank": 8, "User ID": "kendragalloway", "Composite Risk Score": 55.4, "Risk Level": "HIGH", "Markov Risk": 58.9, "SOM Risk": 49.2, "Suspicious Occurrences": 64, "Max Anomaly Score": 3.41},
        {"Rank": 9, "User ID": "test_attacker", "Composite Risk Score": 50.0, "Risk Level": "HIGH", "Markov Risk": 0.0, "SOM Risk": 125.0, "Suspicious Occurrences": 0, "Max Anomaly Score": np.nan},
        {"Rank": 10, "User ID": "jamesmichael", "Composite Risk Score": 54.1, "Risk Level": "HIGH", "Markov Risk": 57.2, "SOM Risk": 48.8, "Suspicious Occurrences": 62, "Max Anomaly Score": 3.22},
    ]

    df = pd.DataFrame(data)
    # The image data is already sorted by Composite Risk Score descending.
    
    # Simulate the alerts structure from the old mock data for 'Deep Dive' section compatibility
    # This is a simplification since the image data doesn't provide granular alerts.
    df['contributing_alerts'] = df.apply(
        lambda row: [
            {"alert_id": f"alert_{row['Rank']}_M", "type": "Markov Deviation", "severity": "high"},
            {"alert_id": f"alert_{row['Rank']}_S", "type": "SOM Anomaly", "severity": "critical"}
        ], axis=1
    )
    # Simulate a 'peer_group' for compatibility with the Deep Dive section
    df['peer_group'] = df.apply(
        lambda row: "admin_users" if row['Rank'] in [1, 3, 5] else "regular_users", axis=1
    )
    
    # Rename columns to match internal keys for downstream logic (like user selection)
    df = df.rename(columns={
        'User ID': 'user_id',
        'Composite Risk Score': 'unified_risk_score',
        'SOM Risk': 'som_score',
    })
    
    return df

@st.cache_data
def load_unified_risk_data():
    """Load the new actual unified risk data."""
    # This function is replaced to load the actual data from the image/table (Task 1)
    return load_top_risky_users_data()

@st.cache_data
def load_sequence_alerts_data():
    """Load mock sequence alerts data."""
    # Data is kept as mock since actual sequence data is not in the image/table
    mock_sequence_alerts = [
        {"session_id": "session_001", "user_id": "dudleynicholas", "score": 0.92, "sequence": ["login", "privilege_change", "data_access", "logout"]},
        {"session_id": "session_002", "user_id": "jacqueline19", "score": 0.85, "sequence": ["login", "data_download", "upload", "suspicious_activity"]},
        {"session_id": "session_003", "user_id": "mitchellclark", "score": 0.80, "sequence": ["login", "data_exfiltration"]},
        {"session_id": "session_004", "user_id": "jamesmichael", "score": 0.70, "sequence": ["login", "unusual_access"]},
    ]
    return pd.DataFrame(mock_sequence_alerts)

@st.cache_data
def load_anomaly_patterns_data():
    """Load mock anomaly patterns data."""
    # Data is adapted from the image data for SOM Anomaly Score compatibility
    anomaly_patterns_data = [
        {"user_id": "dudleynicholas", "som_anomaly_score": 0.625}, # 62.5 / 100
        {"user_id": "jacqueline19", "som_anomaly_score": 0.625},
        {"user_id": "mitchellclark", "som_anomaly_score": 0.584},
        {"user_id": "xreid", "som_anomaly_score": 0.576},
        {"user_id": "hoffmanjennifer", "som_anomaly_score": 0.532},
        {"user_id": "susanrogers", "som_anomaly_score": 0.510},
        {"user_id": "robinsonwilliam", "som_anomaly_score": 0.516},
        {"user_id": "kendragalloway", "som_anomaly_score": 0.492},
        {"user_id": "test_attacker", "som_anomaly_score": 1.25}, # 125.0 / 100
        {"user_id": "jamesmichael", "som_anomaly_score": 0.488},
    ]
    return pd.DataFrame(anomaly_patterns_data)

# MODIFIED: Highlight function to use session state for visual highlight (Task 3)
def highlight_selected_user(row):
    """Highlights the row corresponding to the selected user and the quick-highlighted user."""
    color = ''
    selected_user = st.session_state.get('main_user_select', 'Select a user...')
    quick_highlight_user = st.session_state.get('quick_highlight_user', None)
    
    if row['User ID'] == selected_user:
        # Permanent highlight for the user selected in the main dropdown
        color = 'background-color: #FFD700; color: black; font-weight: bold'
    elif row['User ID'] == quick_highlight_user and st.session_state.get('highlight_active', False):
        # Temporary highlight from graph click
        color = 'background-color: #1e8449; color: white; font-weight: bold; border: 2px solid #2ecc71;'

    return [color] * len(row)
    
def apply_risk_gradient(styler):
    """Apply gradient styling and selected user highlight."""
    # Apply gradient first
    styler = styler.background_gradient(
        subset=['Composite Risk Score'], 
        cmap='RdYlGn_r', 
        vmin=0, 
        vmax=100
    )
    # Apply row highlight last for the visual link. Pass the row data for comparison.
    styler = styler.apply(highlight_selected_user, axis=1)
        
    return styler

# --- Streamlit App Configuration and Setup ---

st.set_page_config(
    page_title="Project Drishti - UEBA Dashboard",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://docs.streamlit.io/', 
        'Report a bug': None,
        'About': "# Project Drishti\n**See the Unseen, Detect the Undetected**"
    }
)

# Custom CSS for UI/UX Fixes (REPLACED/UPDATED)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap');
    
    html, body, [class*="st-"] {
        font-family: 'Poppins', sans-serif !important;
    }
    
    .main-header {
        background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        padding: 2rem;
        border-radius: 16px;
        margin-bottom: 2.5rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .main-header h1 {
        color: #ffffff;
        margin-bottom: 0.5rem;
        font-weight: 700;
        text-align: center;
    }
    
    .main-header p {
        color: #cbd5e1;
        font-size: 1.1rem;
        text-align: center;
        font-weight: 300;
    }
    
    /* Risk Score Styling (Kept for Visual Consistency) */
    .risk-score-high {
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%) !important;
        color: white !important;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 0 25px rgba(220, 38, 38, 0.6);
        border: 2px solid #dc2626;
        animation: pulse-red 2s ease-in-out infinite alternate;
    }
    
    .risk-score-medium {
        background: linear-gradient(135deg, #d97706 0%, #b45309 100%) !important;
        color: white !important;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 0 25px rgba(217, 119, 6, 0.6);
        border: 2px solid #d97706;
        animation: pulse-orange 2s ease-in-out infinite alternate;
    }
    
    .risk-score-low {
        background: linear-gradient(135deg, #16a34a 0%, #15803d 100%) !important;
        color: white !important;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 0 25px rgba(22, 163, 74, 0.6);
        border: 2px solid #16a34a;
        animation: pulse-green 2s ease-in-out infinite alternate;
    }
    
    @keyframes pulse-red {
        from { box-shadow: 0 0 25px rgba(220, 38, 38, 0.6); }
        to { box-shadow: 0 0 35px rgba(220, 38, 38, 0.9), 0 0 45px rgba(220, 38, 38, 0.7); }
    }
    
    @keyframes pulse-orange {
        from { box-shadow: 0 0 25px rgba(217, 119, 6, 0.6); }
        to { box-shadow: 0 0 35px rgba(217, 119, 6, 0.9), 0 0 45px rgba(217, 119, 6, 0.7); }
    }
    
    .logo-container h3{
        text-align: center;
        padding: 1rem 0;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        letter-spacing: 1px;
        text-align: center;
        margin: 0;
        padding: 10px 0;
    }
    
    .footer {
        text-align: center;
        padding: 2rem;
        color: #64748b;
        font-size: 0.9rem;
        border-top: 1px solid #e2e8f0;
        margin-top: 3rem;
    }

    /* --- FINAL UI/UX FIXES START HERE (New/Replaced Section) --- */

    /* FIX 1: Overlapping Arrow Text Removal (Hides 'keyboard arrow down/right/left' text) */

    /* Hide the text content of the sidebar expand/collapse button */
    button[data-testid="base-button-header"] {
        overflow: hidden !important;
        text-indent: -9999px !important; /* Forces text off-screen */
        position: relative !important;
    }
    
    /* Hide the Material Icon text (like 'keyboard_arrow_down') inside expanders, selectboxes, and multiselects */
    /* Targeting the span elements that display the text icon name */
    [data-testid*="stExpander"] span, 
    [data-testid*="stSelectbox"] span,
    [data-testid*="stMultiSelect"] span,
    /* Covers the generic component class used for icons/spans */
    .st-emotion-cache-1kyx2u5 span,
    .st-emotion-cache-1kyx2u5 div { 
        visibility: hidden !important;
        display: none !important; /* Hides the space it takes up too */
    }
    
    /* Ensure the actual icon (SVG) remains visible if it is present */
    [data-testid*="stExpander"] svg,
    [data-testid*="stSelectbox"] svg,
    [data-testid*="stMultiSelect"] svg {
        visibility: visible !important;
        display: block !important;
    }

    div[data-testid="stSidebar"] {
        overflow-x: hidden !important;
    }
    div[data-testid="stSidebarContent"] {
        overflow-x: hidden !important;
    }

    /* --- FINAL UI/UX FIXES END HERE --- */
</style>
""", unsafe_allow_html=True)

def create_interactive_map_simulated(selected_user, mitre_users_list):
    """
    Creates an interactive Plotly figure with simulated SOM data.
    """
    # Simulated data for a 10x10 map
    u_matrix = [[(i + j) / 20 for i in range(10)] for j in range(10)]
    
    # Extended list for more points
    user_list = [
        "dudleynicholas", "jacqueline19", "xreid", "hoffmanjennifer", "lrobinson", 
        "cassandra07", "kendragalloway", "lisa02", "garzaanthony", "janetwilliams", 
        "jamesmichael", "johnsonjoshua", "robinsonwilliam", "maria95", 
        "michellejames", "susanrogers", "jpeterson", "amandasanchez", 
        "mitchellclark", "donaldgarcia", "test_attacker", "emarshall", 
        "enolan", "fnorman", "michaelfisher", "morgan59", "sparsons",
        "user_001", "user_002", "user_003", "user_004", "a_smith", "b_jones", 
        "c_brown", "d_davis", "e_miller", "f_wilson", "g_moore", "h_taylor",
        "i_king", "j_hall", "k_lee", "l_walker", "m_white", "n_adams"
    ]
    
    users = []
    # Use NumPy for deterministic, scattered coordinates
    np.random.seed(42)
    for i, user_id in enumerate(user_list):
        # Coordinates scattered within the 10x10 map
        x_coord = np.random.uniform(0.5, 9.5) 
        y_coord = np.random.uniform(0.5, 9.5)
        attack_score = (i % 5)
        
        users.append({
            'user_id': user_id,
            'x': x_coord,
            'y': y_coord,
            'attack_score': attack_score,
            'benign_score': 0
        })

    # Filter to MITRE users only
    users = [u for u in users if u['user_id'] in mitre_users_list]
    
    heatmap = go.Heatmap(
        z=u_matrix,
        colorscale='Viridis',
        showscale=False
    )
    
    # Use uniform circle markers (dot only, no star)
    user_points = go.Scatter(
        x=[u['x'] for u in users],
        y=[u['y'] for u in users],
        mode='markers',
        hoverinfo='text',
        text=[f"User: {u['user_id']}<br>Attack Score: {u['attack_score']}" for u in users],
        # Store user_id in customdata for click handling
        customdata=[u['user_id'] for u in users], 
        marker=dict(
            size=10, # Uniform size
            color=['#FFD700' if u['user_id'] == selected_user else '#FFFFFF' for u in users], # White dots, Gold highlight
            symbol='circle', # <--- FIXED: ALWAYS CIRCLE (dot), no star
            line=dict(
                color=['#000000' for u in users],
                width=1
            )
        )
    )

    layout = go.Layout(
        title={'text': 'Strategic Anomaly Map (SOM) - Simulated', 'x': 0.5},
        xaxis={'title': 'SOM X-Coordinate', 'showgrid': False, 'zeroline': False, 'range': [0, 10]},
        yaxis={'title': 'SOM Y-Coordinate', 'showgrid': False, 'zeroline': False, 'range': [0, 10]},
        autosize=True,
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False
    )

    fig = go.Figure(data=[heatmap, user_points], layout=layout)
    fig.update_layout(height=500)
    
    # Return figure and user data for Streamlit to handle the click event
    return fig, users

# NEW: Plotly Click Handler (Task 3)
def handle_plot_click(click_data, df):
    """
    Handles a click event on the SOM plot.
    Sets session state variables to trigger table highlight and scroll.
    """
    # The click_data is a dictionary when a click occurs
    if 'points' in click_data and len(click_data['points']) > 0:
        point = click_data['points'][0]
        # The user ID is stored in the customdata field of the trace
        user_id = point['customdata'][0] if 'customdata' in point and len(point['customdata']) > 0 else None
        
        if user_id:
            # 1. Update the main selection box to the clicked user
            st.session_state['main_user_select'] = user_id
            
            # 2. Set the temporary highlight state
            st.session_state['quick_highlight_user'] = user_id
            st.session_state['highlight_active'] = True
            
            # 3. Find the index for scrolling
            # The lookup must use the column name of the *displayed* dataframe: 'User ID'
            try:
                # 'df' passed here is 'display_df' in main(), which has column 'User ID'
                scroll_index = df.index[df['User ID'] == user_id].tolist()[0]
                # Store the index in session state for a Streamlit custom component to use for scrolling
                # Since a custom component is not allowed, we will use an anchor element workaround
                st.session_state['scroll_to_index'] = scroll_index
            except IndexError:
                st.session_state['scroll_to_index'] = 0 # Default to top if not found
            
            # Rerun to apply the new state immediately
            st.rerun()


def main():
    """Main Project Drishti Streamlit application function."""
    
    # Load MITRE data from the uploaded file content (Simulated in session_state)
    mitre_report_content = st.session_state.get('mitre_detection_report.json', '[]')
    mitre_raw_data, mitre_alerts_df = load_mitre_report(mitre_report_content)

    # Load mock data
    unified_risk_df_internal = load_unified_risk_data() # Internal dataframe with standardized keys
    sequence_alerts_df = load_sequence_alerts_data()
    anomaly_patterns_df = load_anomaly_patterns_data()
    
    # Project Drishti Header
    st.markdown("""
    <div class="main-header">
        <h1>Project Drishti</h1>
        <p><strong>See the Unseen, Detect the Undetected</strong></p>
        <p>Advanced User and Entity Behavior Analytics Dashboard</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Combine user lists for the sidebar
    unified_users = unified_risk_df_internal['user_id'].tolist()
    mitre_users = mitre_alerts_df['User ID'].unique().tolist()
    all_users = sorted(list(set(unified_users + mitre_users)))
    
    # Initialize session state for highlighting if not present
    if 'quick_highlight_user' not in st.session_state:
        st.session_state['quick_highlight_user'] = None
    if 'highlight_active' not in st.session_state:
        st.session_state['highlight_active'] = False
        
    # Sidebar Navigation and Filters
    with st.sidebar:
        st.markdown("""<div class="logo-container"><h3 >Project Drishti</h3></div>""", unsafe_allow_html=True)
        
        st.info("Welcome to Project Drishti. Navigate through user risk assessments and dive deep into individual user behaviors for comprehensive security analysis.")
        
        st.markdown("---")
        
        st.subheader("User Investigation")
        # User Selection is the primary link between the SOM plot and the table data
        selected_user = st.selectbox(
            "Select User for Analysis:",
            options=["Select a user..."] + all_users,
            index=0,
            key='main_user_select'
        )
        
        st.markdown("---")
        
        # Quick Statistics
        if not unified_risk_df_internal.empty:
            st.subheader("Dashboard Summary")
            # Use 60.0 as the high risk threshold for the new data scale (60.0 is roughly 60%)
            high_risk_count = len(unified_risk_df_internal[unified_risk_df_internal['unified_risk_score'] > 60.0])
            total_users = len(unified_risk_df_internal)
            avg_risk = unified_risk_df_internal['unified_risk_score'].mean()
            
            st.metric("High Risk Users", f"{high_risk_count}/{total_users}")
            st.metric("Average Risk Score", f"{avg_risk:.2f}")
            st.metric("Total Monitoring", f"{total_users} Users")
        else:
            st.info("Unified Risk Summary Unavailable. Showing MITRE user count.")
            st.metric("Total Monitored Users", f"{len(all_users)} Users")

    
    # Main Content Area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        high_risk_users = unified_risk_df_internal[unified_risk_df_internal['unified_risk_score'] > 60.0]
        if len(high_risk_users) > 0:
            risk_groups = high_risk_users['peer_group'].value_counts()
            st.warning(f"TOP RISKS AT A GLANCE: {len(high_risk_users)} users with Composite Risk Score > 60.0 | Highest peer group: {risk_groups.index[0] if len(risk_groups) > 0 else 'Multiple'} with {risk_groups.iloc[0] if len(risk_groups) > 0 else 0} users")
        else:
            st.info("RISK STATUS: No users currently above 60.0 risk threshold")
    
    with col2:
        st.info("Tip: Select a user from the sidebar or **click a dot on the map** to begin detailed analysis. The table row and SOM dot will be highlighted.")
    
    # Main Unified User Risk Overview Table (Task 1 & 2)
    st.header("Unified User Risk Overview - Top 10 Highest Risk Score")
    st.markdown("Users sorted by Composite Risk Score (highest risk first)")
    
    if not unified_risk_df_internal.empty:
        display_df = unified_risk_df_internal.copy()
        
        # Remove internal columns not in the image and rename to EXACTLY match the image (Task 2)
        display_df = display_df.drop(columns=['contributing_alerts', 'peer_group', 'som_score'])
        
        # Renaming columns to exactly match the reference image
        display_df.columns = [
            'Rank', 
            'User ID', 
            'Composite Risk Score', 
            'Risk Level', 
            'Markov Risk', 
            'Suspicious Occurrences', 
            'Max Anomaly Score'
        ]
        
        # Re-insert 'SOM Risk' based on the original data, but must be careful with column alignment
        # To maintain the structure from the image: Rank, User ID, Composite Risk Score, Risk Level, Markov Risk, SOM Risk, Suspicious Occurrences, Max Anomaly Score
        # Re-load the original data to ensure all columns are present for the styled dataframe
        original_df = load_top_risky_users_data().copy()
        
        # The simplified display_df should now be rebuilt to include 'SOM Risk'
        display_df = original_df[[
            'Rank', 'user_id', 'unified_risk_score', 'Risk Level', 'Markov Risk', 'som_score', 'Suspicious Occurrences', 'Max Anomaly Score'
        ]].copy()
        
        display_df.columns = [
            'Rank', 'User ID', 'Composite Risk Score', 'Risk Level', 'Markov Risk', 'SOM Risk', 'Suspicious Occurrences', 'Max Anomaly Score'
        ]

        # Replace the N/A manually for the dataframe before styling (for the Rank 9 user)
        display_df['Max Anomaly Score'] = display_df['Max Anomaly Score'].fillna('N/A')
        
        # Apply gradient and conditional highlight
        styled_df = display_df.style.pipe(apply_risk_gradient)
        
        st.dataframe(
            styled_df,
            use_container_width=True,
            hide_index=True,
        )
        
        # Check for temporary highlight and reset after a single frame to simulate short pulse
        if st.session_state.get('highlight_active', False):
            # This scrolling method is a simplified workaround
            st.markdown(f'<div id="scroll_target_{st.session_state.get("scroll_to_index", 0)}"></div>', unsafe_allow_html=True)
            # NOTE: Keeping highlight_active as True to visually link click/selection until the next interaction.
    else:
        st.warning("Unified User Risk Overview data is not available.")
    
    # Strategic Anomaly Map Section (Interactive Map)
    st.markdown("---")
    st.subheader("Strategic Anomaly Map (SOM)")
    st.markdown("Visualizing user behavior on the Self-Organizing Map (SOM) to detect outliers. **The selected user is highlighted in Gold.**")

    user_to_highlight = selected_user if selected_user != "Select a user..." else None
    
    # Extract the list of users from the MITRE report
    mitre_user_ids = mitre_alerts_df['User ID'].unique().tolist()
    
    # Call the updated function
    som_fig, som_users_data = create_interactive_map_simulated(user_to_highlight, mitre_user_ids)
    
    # Plotly Click Handler integration (Task 3)
    plotly_click_data = st.plotly_chart(
        som_fig, 
        use_container_width=True, 
        key='som_chart',
        click=True # Enable click events for the Plotly chart
    )
    
    # FIX APPLIED HERE: Robustly check for click data ensuring it is a dictionary (the click event payload)
    if isinstance(plotly_click_data, dict):
        # Check if the event is a genuine single click
        if 'points' in plotly_click_data and len(plotly_click_data['points']) >= 1:
            # Manually call the handler with the dataframe that has the correct display columns
            handle_plot_click(plotly_click_data, display_df)

    st.markdown("""
    The SOM visualizes user behavioral patterns across multi-dimensional clusters, 
    highlighting anomalous users isolated from normal behavioral groups. All plotted points 
    are now **filtered to only include users from the MITRE report** and displayed as 
    uniform **white circles (dots)**, with the **selected user in Gold**.
    """)


    # MITRE ATT&CK Mapper Section (Existing functionality)
    st.markdown("---")
    st.header("MITRE ATT&CK MAPPER: Detected Techniques")
    st.markdown("Alerts mapped to specific adversarial techniques for tactical analysis.")

    technique_counts = mitre_alerts_df.groupby(['Technique ID', 'Technique Name']).size().reset_index(name='Count')
    technique_counts = technique_counts.sort_values('Count', ascending=False)

    col_mitre_1, col_mitre_2 = st.columns([1, 2])

    with col_mitre_1:
        st.subheader("Technique Frequency")
        st.dataframe(
            technique_counts.set_index(['Technique ID', 'Technique Name']),
            use_container_width=True
        )

    with col_mitre_2:
        st.subheader("Full Alert Details")
        st.dataframe(
            mitre_alerts_df,
            use_container_width=True,
            hide_index=True
        )


    # User Deep Dive Section 
    if selected_user and selected_user != "Select a user...":
        st.markdown("---")
        st.header(f"Deep Dive Analysis: {selected_user}")
        
        # Use the internal dataframe for deep dive lookups
        user_data_check = unified_risk_df_internal[unified_risk_df_internal['user_id'] == selected_user]
        user_data = user_data_check.iloc[0] if not user_data_check.empty else None
        
        user_anomaly = anomaly_patterns_df[anomaly_patterns_df['user_id'] == selected_user]
        # Use the raw som_score from user_data (which is already normalized)
        long_term_anomaly_score_raw = user_data['som_score'] if user_data is not None else 0.0 
        # Normalize the SOM Score to a 0-1 range for the metric display if it's over 100
        # Assuming the standard som_score is meant to be an index/magnitude which we display raw/normalized
        # Based on the sample data (62.5, 125.0), we normalize by 100 for display
        long_term_anomaly_score = long_term_anomaly_score_raw / 100.0
        
        col1, col2, col3 = st.columns(3)
        
        if user_data is not None:
            with col1:
                st.markdown("### Composite Risk Score")
                risk_score = user_data['unified_risk_score']
                
                # Risk classification based on the new 0-100 scale from the image
                if risk_score >= 60.0:
                    risk_class = "risk-score-high"
                    risk_label = "HIGH RISK"
                elif risk_score >= 50.0:
                    risk_class = "risk-score-medium"
                    risk_label = "MEDIUM RISK"
                else:
                    risk_class = "risk-score-low"
                    risk_label = "LOW RISK"
                
                st.markdown(f"""
                <div class="{risk_class}">
                    <h2 style="margin: 0; text-align: center;">{risk_label}</h2>
                    <h3 style="margin: 1rem 0; text-align: center;">{risk_score:.1f}</h3>
                    <p style="margin: 0; text-align: center; font-size: 1rem; font-weight: 600;">Overall Risk Assessment</p>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                # Using the simulated peer group for display
                st.metric(
                    label="Peer Group",
                    value=user_data['peer_group'],
                    help="User's assigned peer group for comparison"
                )
            
        else:
            st.warning("Composite Risk Score data is unavailable for this user.")
            
        with col3:
            # Using the simulated Long-Term Anomaly Score (normalized SOM Risk)
            st.metric(
                label="Long-Term Anomaly Score",
                value=f"{(long_term_anomaly_score_raw):.1f}" if not np.isnan(long_term_anomaly_score_raw) else "N/A",
                help="Historical anomaly pattern score (SOM Risk / 100)"
            )
        
        col1, col2 = st.columns(2)
        
        with col1:
            with st.expander("Contributing Alerts Details (Unified System)", expanded=True):
                if user_data is not None and user_data['contributing_alerts']:
                    alerts_data = [{"Alert ID": alert['alert_id'], "Type": alert['type'], "Severity": alert['severity']} for alert in user_data['contributing_alerts']]
                    alerts_df = pd.DataFrame(alerts_data)
                    st.dataframe(alerts_df, use_container_width=True, hide_index=True)
                else:
                    st.info("No contributing alerts from the unified system for this user.")
        
        with col2:
            with st.expander("Full Sequence Alert Details (Markov Model)"):
                user_sequences = sequence_alerts_df[sequence_alerts_df['user_id'] == selected_user]
                
                if not user_sequences.empty:
                    sequence_display = user_sequences.copy()
                    sequence_display['score'] = (sequence_display['score'] * 100).round(0).astype(int)
                    sequence_display['sequence'] = sequence_display['sequence'].apply(lambda x: " → ".join(x))
                    sequence_display.columns = ['Session ID', 'User ID', 'Score', 'Behavioral Sequence']
                    
                    st.dataframe(
                        sequence_display,
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info("No specific high-risk sequence alerts found for this user from Markov.")
        
        with st.expander(f"MITRE ATT&CK Alerts for {selected_user}", expanded=True):
            user_mitre_alerts = mitre_alerts_df[mitre_alerts_df['User ID'] == selected_user]
            
            if not user_mitre_alerts.empty:
                st.dataframe(user_mitre_alerts[['Source', 'Technique ID', 'Technique Name', 'Confidence', 'Description']], use_container_width=True, hide_index=True)
            else:
                st.info(f"No MITRE ATT&CK techniques detected for user **{selected_user}** in the latest report.")

        with st.expander("User Anomaly Patterns Analysis"):
            if user_data is not None:
                st.subheader("SOM Anomaly Score Analysis")
                som_score_display = f"{(long_term_anomaly_score_raw):.1f}" if not np.isnan(long_term_anomaly_score_raw) else "N/A"
                
                st.metric(
                    label="Current SOM Anomaly Score (0-100+)",
                    value=som_score_display,
                    help="Self-Organizing Map anomaly detection score"
                )
                
                if long_term_anomaly_score > 0.7:
                    st.warning("High Anomaly: This user's behavior pattern significantly deviates from normal patterns.")
                elif long_term_anomaly_score > 0.4:
                    st.info("Moderate Anomaly: Some behavioral deviations detected.")
                else:
                    st.success("Low Anomaly: User behavior appears within normal parameters.")
            else:
                st.info("No anomaly pattern data available for this user.")
    
    else:
        st.info("Select a user from the sidebar to begin detailed analysis")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div class="footer">
        <strong>Project Drishti v2.0</strong> | Real-time Behavioral Risk Monitoring | Professional UEBA Dashboard
    </div>
    """, unsafe_allow_html=True)
    
    # NOTE: The block for checking plotly_click_data remains here, as it needs to access
    # the returned value from st.plotly_chart in the run where the click occurred.


if __name__ == "__main__":
    # Simulate loading the JSON file content into session state
    st.session_state['mitre_detection_report.json'] = """
[
    {
        "sequence_id": "Markov_User_1_TopRisk",
        "user_id": "dudleynicholas",
        "raw_data": {
            "user_id": "dudleynicholas",
            "score": 0.0,
            "sequence": "sys_windows_event"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_2_TopRisk",
        "user_id": "jacqueline19",
        "raw_data": {
            "user_id": "jacqueline19",
            "score": 0.0,
            "sequence": "process_start_None"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_3_TopRisk",
        "user_id": "xreid",
        "raw_data": {
            "user_id": "xreid",
            "score": 0.0,
            "sequence": "file_DOWNLOAD"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_4_TopRisk",
        "user_id": "hoffmanjennifer",
        "raw_data": {
            "user_id": "hoffmanjennifer",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_5_TopRisk",
        "user_id": "lrobinson",
        "raw_data": {
            "user_id": "lrobinson",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_6_TopRisk",
        "user_id": "cassandra07",
        "raw_data": {
            "user_id": "cassandra07",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_7_TopRisk",
        "user_id": "kendragalloway",
        "raw_data": {
            "user_id": "kendragalloway",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_8_TopRisk",
        "user_id": "lisa02",
        "raw_data": {
            "user_id": "lisa02",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_9_TopRisk",
        "user_id": "garzaanthony",
        "raw_data": {
            "user_id": "garzaanthony",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_10_TopRisk",
        "user_id": "janetwilliams",
        "raw_data": {
            "user_id": "janetwilliams",
            "score": 0.0,
            "sequence": "process_start_None"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_11_TopRisk",
        "user_id": "jamesmichael",
        "raw_data": {
            "user_id": "jamesmichael",
            "score": 0.0,
            "sequence": "process_start_None"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_12_TopRisk",
        "user_id": "johnsonjoshua",
        "raw_data": {
            "user_id": "johnsonjoshua",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_13_TopRisk",
        "user_id": "robinsonwilliam",
        "raw_data": {
            "user_id": "robinsonwilliam",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_14_TopRisk",
        "user_id": "maria95",
        "raw_data": {
            "user_id": "maria95",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_15_TopRisk",
        "user_id": "michellejames",
        "raw_data": {
            "user_id": "michellejames",
            "score": 0.0,
            "sequence": "sys_windows_event"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_16_TopRisk",
        "user_id": "susanrogers",
        "raw_data": {
            "user_id": "susanrogers",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_17_TopRisk",
        "user_id": "jpeterson",
        "raw_data": {
            "user_id": "jpeterson",
            "score": 0.0,
            "sequence": "file_DELETE"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_18_TopRisk",
        "user_id": "amandasanchez",
        "raw_data": {
            "user_id": "amandasanchez",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_19_TopRisk",
        "user_id": "mitchellclark",
        "raw_data": {
            "user_id": "mitchellclark",
            "score": 0.0,
            "sequence": "auth_login"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "confidence": 0.7,
                "rule_matched": "markov_suspicious_login_pattern",
                "description": "Suspicious login activity detected (Markov)",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "Markov_User_20_TopRisk",
        "user_id": "donaldgarcia",
        "raw_data": {
            "user_id": "donaldgarcia",
            "score": 0.0,
            "sequence": "sys_windows_event"
        },
        "source": "markov",
        "detected_techniques": [
            {
                "id": "TA0009",
                "name": "Collection",
                "confidence": 0.55,
                "rule_matched": "markov_max_anomaly_score_fallback",
                "description": "Sequence had maximum anomaly (score 0.0) but matched no specific pattern.",
                "evidence": {
                    "anomaly_score": 1.0,
                    "source": "markov"
                }
            }
        ]
    },
    {
        "sequence_id": "SOM_User_1",
        "user_id": "test_attacker",
        "raw_data": {
            "user_id": "test_attacker",
            "flagged_epochs": 10,
            "total_epochs": 10,
            "attack_score": 4,
            "benign_score": 0
        },
        "source": "som",
        "detected_techniques": [
            {
                "id": "T1070.004",
                "name": "Indicator Removal: File Deletion",
                "confidence": 0.9,
                "rule_matched": "som_high_attack_score",
                "description": "SOM flagged high attack-like behavior (0.40) over time.",
                "evidence": {
                    "attack_score": 4,
                    "anomaly_metric": 0.4,
                    "source": "som"
                }
            }
        ]
    },
    {
        "sequence_id": "SOM_User_2",
        "user_id": "emarshall",
        "raw_data": {
            "user_id": "emarshall",
            "flagged_epochs": 10,
            "total_epochs": 10,
            "attack_score": 0,
            "benign_score": 2
        },
        "source": "som",
        "detected_techniques": [
            {
                "id": "T1090",
                "name": "Proxy",
                "confidence": 0.65,
                "rule_matched": "som_always_flagged_no_attack_score",
                "description": "User consistently flagged, but low attack score, suggesting an unusual persistent process.",
                "evidence": {
                    "flagged_epochs": 10,
                    "source": "som"
                }
            }
        ]
    },
    {
        "sequence_id": "SOM_User_3",
        "user_id": "enolan",
        "raw_data": {
            "user_id": "enolan",
            "flagged_epochs": 10,
            "total_epochs": 10,
            "attack_score": 0,
            "benign_score": 2
        },
        "source": "som",
        "detected_techniques": [
            {
                "id": "T1090",
                "name": "Proxy",
                "confidence": 0.65,
                "rule_matched": "som_always_flagged_no_attack_score",
                "description": "User consistently flagged, but low attack score, suggesting an unusual persistent process.",
                "evidence": {
                    "flagged_epochs": 10,
                    "source": "som"
                }
            }
        ]
    },
    {
        "sequence_id": "SOM_User_4",
        "user_id": "fnorman",
        "raw_data": {
            "user_id": "fnorman",
            "flagged_epochs": 10,
            "total_epochs": 10,
            "attack_score": 0,
            "benign_score": 2
        },
        "source": "som",
        "detected_techniques": [
            {
                "id": "T1090",
                "name": "Proxy",
                "confidence": 0.65,
                "rule_matched": "som_always_flagged_no_attack_score",
                "description": "User consistently flagged, but low attack score, suggesting an unusual persistent process.",
                "evidence": {
                    "flagged_epochs": 10,
                    "source": "som"
                }
            }
        ]
    },
    {
        "sequence_id": "SOM_User_5",
        "user_id": "michaelfisher",
        "raw_data": {
            "user_id": "michaelfisher",
            "flagged_epochs": 10,
            "total_epochs": 10,
            "attack_score": 0,
            "benign_score": 2
        },
        "source": "som",
        "detected_techniques": [
            {
                "id": "T1090",
                "name": "Proxy",
                "confidence": 0.65,
                "rule_matched": "som_always_flagged_no_attack_score",
                "description": "User consistently flagged, but low attack score, suggesting an unusual persistent process.",
                "evidence": {
                    "flagged_epochs": 10,
                    "source": "som"
                }
            }
        ]
    },
    {
        "sequence_id": "SOM_User_6",
        "user_id": "morgan59",
        "raw_data": {
            "user_id": "morgan59",
            "flagged_epochs": 10,
            "total_epochs": 10,
            "attack_score": 0,
            "benign_score": 2
        },
        "source": "som",
        "detected_techniques": [
            {
                "id": "T1090",
                "name": "Proxy",
                "confidence": 0.65,
                "rule_matched": "som_always_flagged_no_attack_score",
                "description": "User consistently flagged, but low attack score, suggesting an unusual persistent process.",
                "evidence": {
                    "flagged_epochs": 10,
                    "source": "som"
                }
            }
        ]
    },
    {
        "sequence_id": "SOM_User_7",
        "user_id": "sparsons",
        "raw_data": {
            "user_id": "sparsons",
            "flagged_epochs": 10,
            "total_epochs": 10,
            "attack_score": 0,
            "benign_score": 2
        },
        "source": "som",
        "detected_techniques": [
            {
                "id": "T1090",
                "name": "Proxy",
                "confidence": 0.65,
                "rule_matched": "som_always_flagged_no_attack_score",
                "description": "User consistently flagged, but low attack score, suggesting an unusual persistent process.",
                "evidence": {
                    "flagged_epochs": 10,
                    "source": "som"
                }
            }
        ]
    }
]
"""
    main()