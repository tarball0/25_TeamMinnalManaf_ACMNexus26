from __future__ import annotations

import json
import shutil
import subprocess

TRUSTED_PUBLISHERS = [
    "Microsoft Corporation",
    "Google LLC",
    "Adobe Inc.",
    "Mozilla Corporation",
    "VideoLAN",
    "Notepad++ Team",
]


def get_authenticode_info(file_path: str) -> dict:
    escaped_path = file_path.replace("'", "''")
    ps = rf"""
$sig = Get-AuthenticodeSignature -LiteralPath '{escaped_path}';
[pscustomobject]@{{
    status = [string]$sig.Status
    status_message = [string]$sig.StatusMessage
    signature_type = [string]$sig.SignatureType
    is_os_binary = [bool]$sig.IsOSBinary
    subject = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Subject }} else {{ "" }}
    issuer = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Issuer }} else {{ "" }}
    thumbprint = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Thumbprint }} else {{ "" }}
}} | ConvertTo-Json -Compress
"""

    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        return {
            "available": False,
            "status": "Unavailable",
            "status_message": "PowerShell not found",
            "subject": "",
            "issuer": "",
            "thumbprint": "",
            "signature_type": "",
            "is_os_binary": False,
            "trusted_publisher": False,
        }

    try:
        proc = subprocess.run(
            [shell, "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {
                "available": False,
                "status": "Error",
                "status_message": proc.stderr.strip() or "Signature check failed",
                "subject": "",
                "issuer": "",
                "thumbprint": "",
                "signature_type": "",
                "is_os_binary": False,
                "trusted_publisher": False,
            }

        data = json.loads(proc.stdout)
        data["available"] = True
        data["trusted_publisher"] = is_trusted_publisher(data)
        return data
    except Exception as exc:
        return {
            "available": False,
            "status": "Error",
            "status_message": str(exc),
            "subject": "",
            "issuer": "",
            "thumbprint": "",
            "signature_type": "",
            "is_os_binary": False,
            "trusted_publisher": False,
        }


def is_trusted_publisher(sig_info: dict) -> bool:
    if sig_info.get("status") != "Valid":
        return False

    subject = (sig_info.get("subject") or "").lower()
    return any(publisher.lower() in subject for publisher in TRUSTED_PUBLISHERS)


def has_embedded_signature(sig_info: dict) -> bool:
    if not sig_info:
        return False

    if sig_info.get("status") == "NotSigned":
        return False

    return bool(
        sig_info.get("subject")
        or sig_info.get("thumbprint")
        or (
            sig_info.get("signature_type")
            and sig_info.get("signature_type") != "None"
        )
    )


def signature_score_adjustment(sig_info: dict) -> tuple[int, str]:
    if sig_info.get("status") == "Valid" and is_trusted_publisher(sig_info):
        if sig_info.get("is_os_binary"):
            return -45, "Valid Microsoft OS signature strongly reduced the risk score."
        return -30, "Valid signature from trusted publisher reduced the risk score."
    if sig_info.get("status") == "Valid":
        return -15, "Valid signature reduced the risk score, but the publisher is not in the trusted allowlist."
    if sig_info.get("status") == "NotSigned":
        return 15, "File is not signed."
    if not sig_info.get("available"):
        return 0, f"Signature check unavailable: {sig_info.get('status_message', 'unknown reason')}."
    return 25, f"Signature issue: {sig_info.get('status', 'Unknown')}."


def should_run_cnn(sig_info: dict, pe_info: dict) -> tuple[bool, str | None]:
    if has_embedded_signature(sig_info):
        return False, "File is signed, so CNN evidence is ignored."

    packed = bool(pe_info.get("packed"))
    high_entropy = bool(pe_info.get("high_entropy"))
    suspicious_imports = bool(pe_info.get("suspicious_imports"))
    bad_overlay = float(pe_info.get("overlay_ratio", 0.0)) > 0.15

    if is_trusted_publisher(sig_info) and not (packed or high_entropy or suspicious_imports or bad_overlay):
        return False, "Trusted valid signature and PE structure looks normal."

    return True, None
