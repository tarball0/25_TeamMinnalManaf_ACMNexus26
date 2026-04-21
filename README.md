# Minnalize

Minnalize is a malware triage tool that prioritizes **computer vision** for binary classification. By converting executable binaries into grayscale images, it identifies malicious structural patterns using a fine-tuned **Convolutional Neural Network (CNN)**. This visual approach is augmented by traditional static PE header analysis and Authenticode signature verification.

The project treats binaries as spatial data, preserving byte-sequence correlations to make malicious fingerprints visible to deep learning models that traditional static analysis might miss.

## Logic Flow

```text
    [ File Ingestion ]
           |
           v
  [ Signature Check ] ----(Trusted)----> [ Low Suspicion ]
           |                                     |
      (Unsigned)                                 |
           |                                     |
           v                                     |
 [ PE Header Parsing ] <-------------------------'
           |
           v
 [ Binary-to-Image ]  <-- (Core Analysis)
           |
           v
  [ CNN Inference ]
           |
           v
[ Hybrid Scoring Engine ]
           |
           v
    [ Final Report ]
```

## Features

*   **Deep Learning Classification (CNN):** The core engine employs a fine-tuned EfficientNet-B0 model (PyTorch) trained on image representations of both benign and malicious binary samples to detect visual fingerprints of malware.
*   **Binary-to-Image Conversion:** Transforms .exe files into grayscale images using Nataraj-style width mapping. This process makes hidden malicious patterns—such as packed code, encrypted sections, or resource padding—visible to vision models.
*   **Static PE Analysis:** Extracts features such as section entropy, import counts, and suspicious API calls (e.g., VirtualAlloc, LoadLibrary) using the `pefile` library.
*   **Authenticode Signature Verification:** Utilizes Windows PowerShell features (`Get-AuthenticodeSignature`) to verify file integrity and check for trusted publishers.
*   **Hybrid Scoring Engine:** Aggregates visual signals (70% weight), static rules (30% weight), and signature metadata into a final suspicion score (0-100).
*   **Report Generation:** Provides human-readable explanations for the assigned risk level, detailing specific PE anomalies or CNN confidence margins.
*   **Electron Interface:** A desktop UI built with Electron for seamless file ingestion and result visualization.

## Technical Stack

*   **Frontend:** Electron, JavaScript, HTML, CSS.
*   **Backend:** Python 3.
*   **Libraries:** PyTorch, Torchvision, NumPy, Pillow, pefile.
*   **System Integration:** Windows PowerShell.

## Architecture

1.  **Ingestion:** The user selects a file via the Electron UI.
2.  **Signature Check:** The system first checks for an Authenticode signature. Valid signatures from trusted publishers (e.g., Microsoft, Google) significantly reduce the suspicion score.
3.  **PE Parsing:** The PE header is parsed for structural anomalies, high entropy (indicating packing or encryption), and suspicious imports.
4.  **Visualization (Core):** The binary is mapped to a grayscale image. The image width is adjusted based on file size to maintain consistent pattern density for the CNN.
5.  **CNN Inference:** The image is passed to EfficientNet-B0 to detect malicious visual fingerprints. This is the primary driver for the final verdict.
6.  **Fusion:** The final verdict uses a weighted blend of the CNN output (70%) and PE rules (30%) for unsigned files.

## Authors

*   [Fahad](https://github.com/Fahad-uz)
*   [Chris Paul](https://github.com/tarball0)
*   [Aidan Jason](https://github.com/AidanJ07)

## Requirements

*   **OS:** Windows (Required for full PowerShell signature verification).
*   **Python:** 3.8+ with `torch`, `torchvision`, `pefile`, and `numpy`.
*   **Node.js:** For the Electron frontend.
