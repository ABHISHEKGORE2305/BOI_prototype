import time
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# =========================
# CONFIG
# =========================

BACKEND_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="APK Fraud Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Generative AI APK Fraud Analyzer")
st.markdown(
    """
Upload an APK file and receive:

- Malware Risk Score
- SHAP Explainability
- AI Security Report
"""
)

# =========================
# FILE UPLOAD
# =========================

uploaded_file = st.file_uploader(
    "Upload APK File",
    type=["apk"]
)

if uploaded_file:

    st.info("Uploading APK to backend...")

    try:

        files = {
            "file": (
                uploaded_file.name,
                uploaded_file,
                "application/octet-stream"
            )
        }

        upload_response = requests.post(
            f"{BACKEND_URL}/upload",
            files=files,
            timeout=60
        )

        if upload_response.status_code != 200:
            st.error(
                f"Upload failed: {upload_response.text}"
            )
            st.stop()

        upload_data = upload_response.json()

        task_id = upload_data["task_id"]

        st.success(
            f"Analysis Started | Task ID: {task_id}"
        )

    except Exception as e:
        st.error(str(e))
        st.stop()

    # =========================
    # POLLING
    # =========================

    status_placeholder = st.empty()

    with st.spinner("Analyzing APK..."):

        while True:

            try:

                response = requests.get(
                    f"{BACKEND_URL}/status/{task_id}",
                    timeout=30
                )

                data = response.json()

                status = data["status"]

                status_placeholder.info(
                    f"Current Status: {status}"
                )

                if status == "completed":
                    break

                if status == "failed":
                    st.error(
                        "Analysis failed."
                    )
                    st.stop()

                time.sleep(2)

            except Exception as e:
                st.error(str(e))
                st.stop()

    # =========================
    # RESULTS
    # =========================

    score = data.get("malware_score") or 0

    report = data.get(
        "llm_report",
        "No report available."
    )

    shap_data = data.get(
        "shap_data",
        {}
    )

    st.success("Analysis Complete")

    # =========================
    # RISK LEVEL
    # =========================

    if score >= 80:
        risk_level = "HIGH"
    elif score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # =========================
    # DASHBOARD LAYOUT
    # =========================

    col1, col2 = st.columns([1, 1])

    # =========================
    # LEFT SIDE
    # =========================

    with col1:

        st.subheader("Risk Assessment")

        st.metric(
            label="Fraud Risk Score",
            value=f"{score:.2f}%"
        )

        if risk_level == "HIGH":
            st.error(f"{risk_level} RISK")
        elif risk_level == "MEDIUM":
            st.warning(f"{risk_level} RISK")
        else:
            st.success(f"{risk_level} RISK")

        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=score,
                title={
                    "text": "Fraud Risk Score"
                },
                gauge={
                    "axis": {
                        "range": [0, 100]
                    }
                }
            )
        )

        st.plotly_chart(
            gauge,
            use_container_width=True
        )

    # =========================
    # RIGHT SIDE
    # =========================

    with col2:

        st.subheader("AI Security Report")

        st.markdown(report)

    # =========================
    # SHAP CHART
    # =========================

    st.subheader(
        "Top SHAP Feature Importance"
    )

    if shap_data:

        df = pd.DataFrame(
            {
                "Feature": list(
                    shap_data.keys()
                ),
                "Importance": list(
                    shap_data.values()
                )
            }
        )

        fig = px.bar(
            df,
            x="Importance",
            y="Feature",
            orientation="h",
            title="Most Influential Features"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:
        st.warning(
            "No SHAP data available."
        )