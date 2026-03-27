import tempfile
import os
from pathlib import Path

import matplotlib.pyplot as plt
import streamlit as st
from PIL import Image

from app.main import analyze_file

st.set_page_config(page_title="Minnalize", layout="wide")

st.title("Minnalize")
st.write(
    "Upload an executable file to generate a grayscale byte image, "
    "extract PE features, and compute a simple suspiciousness score."
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
                ax.set_title("Rule-Based Suspicion Score")
                st.pyplot(fig)

            st.subheader("PE Features")
            pe_info = result["pe_info"]

            st.json({
                "is_pe": pe_info["is_pe"],
                "num_sections": pe_info["num_sections"],
                "section_names": pe_info["section_names"],
                "section_entropies": pe_info["section_entropies"],
                "avg_section_entropy": pe_info["avg_section_entropy"],
                "imports_count": pe_info["imports_count"],
                "suspicious_section_names": pe_info["suspicious_section_names"],
                "entry_point": pe_info["entry_point"],
            })

            st.subheader("Explanation")
            st.text(result["explanation"])

        except Exception as e:
            st.error(f"Analysis failed: {e}")
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
