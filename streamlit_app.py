import os
import tempfile
from pathlib import Path

import matplotlib.pyplot as plt
import streamlit as st
from PIL import Image

from app.main import analyze_file

st.set_page_config(page_title="Minnalize", layout="wide")

st.title("Minnalize")
st.write(
    "Upload an executable file to generate a grayscale byte image, "
    "extract PE features, verify its Windows signature, and compute a suspiciousness score."
)

uploaded_file = st.file_uploader("Upload an EXE/DLL file", type=["exe", "dll"])

if uploaded_file is not None:
    if uploaded_file.size > 50 * 1024 * 1024:
        st.error("File size exceeds 50MB limit.")
    else:
        suffix = Path(uploaded_file.name).suffix
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(uploaded_file.read())
                temp_path = tmp.name

            result = analyze_file(temp_path)

            col1, col2 = st.columns([1, 1])

            with col1:
                st.subheader("Grayscale Image")
                try:
                    img = Image.open(result["image_info"]["image_path"])
                    st.image(img, caption=result["file_name"], use_container_width=True)
                except FileNotFoundError:
                    st.error("Could not load generated image.")

            with col2:
                st.subheader("Suspicion Score")
                score = result["score_info"]["score"]
                label = result["score_info"]["label"]

                st.metric("Score", f"{score}/100")
                st.write(f"**Classification:** {label}")

                fig, ax = plt.subplots(figsize=(6, 3))
                ax.bar(["Suspicion Score"], [score])
                ax.set_ylim(0, 100)
                ax.set_ylabel("Score")
                ax.set_title("Suspicion Score")
                st.pyplot(fig)

            signature_info = result.get("signature_info", {})
            st.subheader("Signature")
            st.json(
                {
                    "status": signature_info.get("status"),
                    "trusted_publisher": signature_info.get("trusted_publisher"),
                    "subject": signature_info.get("subject"),
                    "issuer": signature_info.get("issuer"),
                    "status_message": signature_info.get("status_message"),
                }
            )

            st.subheader("PE Features")
            pe_info = result["pe_info"]
            st.json(
                {
                    "is_pe": pe_info["is_pe"],
                    "num_sections": pe_info["num_sections"],
                    "section_names": pe_info["section_names"],
                    "section_entropies": pe_info["section_entropies"],
                    "avg_section_entropy": pe_info["avg_section_entropy"],
                    "imports_count": pe_info["imports_count"],
                    "suspicious_section_names": pe_info["suspicious_section_names"],
                    "suspicious_api_imports": pe_info["suspicious_api_imports"],
                    "entry_point": pe_info["entry_point"],
                    "entry_point_section": pe_info["entry_point_section"],
                    "entry_point_section_entropy": pe_info["entry_point_section_entropy"],
                    "tls_callbacks": pe_info["tls_callbacks"],
                    "has_certificate": pe_info["has_certificate"],
                    "certificate_size": pe_info["certificate_size"],
                    "checksum_matches": pe_info["checksum_matches"],
                    "timestamp_iso": pe_info["timestamp_iso"],
                    "timestamp_is_future": pe_info["timestamp_is_future"],
                    "timestamp_is_very_old": pe_info["timestamp_is_very_old"],
                    "timestamp_is_zero": pe_info["timestamp_is_zero"],
                    "resource_types": pe_info["resource_types"],
                    "resource_count": pe_info["resource_count"],
                    "section_size_anomalies": pe_info["section_size_anomalies"],
                    "packed": pe_info["packed"],
                    "high_entropy": pe_info["high_entropy"],
                    "suspicious_imports": pe_info["suspicious_imports"],
                }
            )

            st.subheader("Explanation")
            st.text(result["explanation"])

        except Exception as e:
            st.error(f"Analysis failed: {e}")
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
