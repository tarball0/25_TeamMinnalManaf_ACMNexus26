import streamlit as st
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
import pandas as pd

# Import our custom modules
import parser
import features
import model
import explain

st.set_page_config(page_title="Adaptive Log Lens", layout="wide")
st.title("🛡️ Adaptive Log Lens")
st.markdown("Modular, Unsupervised Threat Detection Pipeline.")

# --- PIPELINE EXECUTION ---
with st.spinner("Ingesting and analyzing logs..."):
    df_raw = parser.parse_auth_log()
    if df_raw.empty:
        st.error("No data found in data/auth.log. Please generate test data.")
        st.stop()
        
    df_matrix = features.build_feature_matrix(df_raw)
    
    # UI Control for Sensitivity
    sensitivity = st.sidebar.slider("Anomaly Sensitivity", 1, 15, 5) / 100.0
    
    df_scored = model.detect_anomalies(df_matrix, contamination=sensitivity)

# Separate normal vs anomalous
anomalies = df_scored[df_scored['anomaly_score'] == -1]
normal = df_scored[df_scored['anomaly_score'] == 1]

# --- METRICS ---
c1, c2, c3 = st.columns(3)
c1.metric("Raw Events Parsed", len(df_raw))
c2.metric("Unique Entities (IPs)", len(df_scored))
c3.metric("Threats Detected", len(anomalies), delta_color="inverse")
st.divider()

# --- VISUALIZATION ---
st.subheader("Behavioral Matrix Heatmaps")
feature_cols = ['total_events', 'failed_logins', 'success_logins', 'unique_ips', 'hour_of_day']

# Scale the data for the colors
scaler = StandardScaler()
scaled_data = pd.DataFrame(scaler.fit_transform(df_scored[feature_cols]), columns=feature_cols)

# ---> THE FIX: Attach the formatted timestamps to the Y-axis <---
scaled_data.index = df_scored['timestamp'].dt.strftime('%H:%M')

# Add the scores back in so we can filter by them
scaled_data['score'] = df_scored['anomaly_score'].values

colA, colB = st.columns(2)
with colA:
    st.markdown("**Baseline Activity (Normal)**")
    fig1, ax1 = plt.subplots(figsize=(6, 3))
    sns.heatmap(scaled_data[scaled_data['score'] == 1].drop('score', axis=1).head(10), cmap="Blues", ax=ax1)
    st.pyplot(fig1)

with colB:
    st.markdown("**🚨 Flagged Anomalies**")
    fig2, ax2 = plt.subplots(figsize=(6, 3))
    sns.heatmap(scaled_data[scaled_data['score'] == -1].drop('score', axis=1), cmap="Reds", ax=ax2)
    st.pyplot(fig2)

st.divider()

# --- INCIDENT RESPONSE ---
st.subheader("LLM Incident Explainer")
if not anomalies.empty:
    target_time = st.selectbox("Select Flagged Time Window:", anomalies['timestamp'].astype(str).tolist())
    target_time = pd.to_datetime(target_time)
    incident_row = anomalies[anomalies['timestamp'] == target_time].iloc[0]
    st.write(f"**Telemetry for Window: {target_time}:**")
    st.json(incident_row[feature_cols].to_dict())    

    if st.button("Generate AI Report"):
        with st.spinner("Querying LLM..."):
            report = explain.analyze_incident(incident_row)
            st.warning(report)
else:
    st.success("System normal. No anomalies detected.")
