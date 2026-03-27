# Executable Grayscale Analyzer

A hackathon MVP that analyzes executable files by:

1. Reading raw bytes from the uploaded file
2. Converting bytes into a grayscale image
3. Extracting PE structure features
4. Computing a simple rule-based suspicious score
5. Explaining the result in plain language

## Why this project?

Packed or suspicious binaries often show unusual entropy, low import counts, strange section names, or abnormal byte patterns. This MVP gives a visual and explainable first-pass analysis.

## Features

- Upload `.exe` or `.dll`
- Convert bytes to grayscale PNG
- Extract PE features using `pefile`
- Compute rule-based suspicion score
- Show explanation for demo/judging

## Tech Stack

- Python
- Streamlit
- pefile
- NumPy
- Pillow
- Matplotlib

## Run locally

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
