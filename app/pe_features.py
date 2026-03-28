from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pefile


KNOWN_SUSPICIOUS_SECTION_NAMES = {
    ".upx",
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".adata",
    ".packed",
    "pec1",
    "pec2",
    ".petite",
    ".themida",
    ".vmp0",
    ".vmp1",
}

SUSPICIOUS_API_NAMES = {
    "adjusttokenprivileges",
    "checkremotedebuggerpresent",
    "connect",
    "createprocess",
    "createremotethread",
    "getprocaddress",
    "internetopen",
    "internetopenurl",
    "internetreadfile",
    "isdebuggerpresent",
    "loadlibrary",
    "ntunmapviewofsection",
    "openprocess",
    "readprocessmemory",
    "recv",
    "regcreatekey",
    "regsetvalue",
    "send",
    "setwindowshook",
    "shellexecute",
    "shellexecutea",
    "shellexecutew",
    "socket",
    "urldownloadtofile",
    "virtualalloc",
    "virtualprotect",
    "winexec",
    "writeprocessmemory",
    "wsastartup",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def _safe_section_name(section) -> str:
    return section.Name.decode(errors="ignore").strip("\x00").strip()


def _section_flags(section) -> dict[str, bool]:
    chars = int(section.Characteristics)
    return {
        "readable": bool(chars & 0x40000000),
        "writable": bool(chars & 0x80000000),
        "executable": bool(chars & 0x20000000),
    }


def _safe_import_name(imp) -> str:
    raw_name = getattr(imp, "name", None)
    if not raw_name:
        return ""
    try:
        return raw_name.decode(errors="ignore")
    except Exception:
        return str(raw_name)


def _normalize_import_name(name: str) -> str:
    lower_name = name.lower()
    if len(lower_name) > 1 and lower_name[-1] in {"a", "w"}:
        candidate = lower_name[:-1]
        if candidate in SUSPICIOUS_API_NAMES:
            return candidate
    return lower_name


def _suspicious_api_names(import_names: list[str]) -> list[str]:
    hits: list[str] = []
    for name in import_names:
        if _normalize_import_name(name) in SUSPICIOUS_API_NAMES:
            hits.append(name)
    return sorted(set(hits))


def _default_result(file_size: int) -> dict:
    return {
        "file_size": file_size,
        "is_pe": False,
        "num_sections": 0,
        "section_names": [],
        "section_entropies": [],
        "avg_section_entropy": 0.0,
        "max_section_entropy": 0.0,
        "high_entropy_sections": [],
        "imports_count": 0,
        "import_names": [],
        "imported_dlls": [],
        "suspicious_api_imports": [],
        "has_debug": False,
        "has_tls": False,
        "tls_callbacks": 0,
        "entry_point": None,
        "entry_point_section": None,
        "entry_point_section_entropy": None,
        "suspicious_section_names": [],
        "overlay_size": 0,
        "overlay_ratio": 0.0,
        "executable_writable_sections": [],
        "resource_types": [],
        "resource_count": 0,
        "has_resources": False,
        "has_certificate": False,
        "certificate_size": 0,
        "has_valid_checksum_field": False,
        "checksum_matches": None,
        "timestamp": None,
        "timestamp_iso": None,
        "timestamp_is_zero": False,
        "timestamp_is_future": False,
        "timestamp_is_very_old": False,
        "section_size_anomalies": [],
        "has_section_size_anomalies": False,
        "high_entropy": False,
        "suspicious_imports": False,
        "packed": False,
        "parse_error": None,
    }


def extract_pe_features(file_path: str) -> dict:
    file_size = Path(file_path).stat().st_size
    result = _default_result(file_size)

    try:
        pe = pefile.PE(file_path, fast_load=False)
        try:
            result["is_pe"] = True
            result["num_sections"] = len(pe.sections)
            result["entry_point"] = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

            section_names: list[str] = []
            section_entropies: list[float] = []
            suspicious_names: list[str] = []
            high_entropy_sections: list[str] = []
            exec_write_sections: list[str] = []
            section_entropy_by_name: dict[str, float] = {}
            section_size_anomalies: list[str] = []

            for section in pe.sections:
                name = _safe_section_name(section)
                section_names.append(name)

                entropy = round(shannon_entropy(section.get_data()), 4)
                section_entropies.append(entropy)
                section_entropy_by_name[name] = entropy

                lower_name = name.lower()
                if (
                    lower_name in KNOWN_SUSPICIOUS_SECTION_NAMES
                    or "upx" in lower_name
                    or "pack" in lower_name
                    or "vmprotect" in lower_name
                    or "themida" in lower_name
                ):
                    suspicious_names.append(name)

                if entropy >= 7.2:
                    high_entropy_sections.append(name)

                flags = _section_flags(section)
                if flags["executable"] and flags["writable"]:
                    exec_write_sections.append(name)

                virtual_size = int(getattr(section, "Misc_VirtualSize", 0) or 0)
                raw_size = int(getattr(section, "SizeOfRawData", 0) or 0)
                if virtual_size > 0 and raw_size > 0:
                    larger = max(virtual_size, raw_size)
                    smaller = max(1, min(virtual_size, raw_size))
                    if (larger / smaller) >= 8.0:
                        section_size_anomalies.append(name)

            result["section_names"] = section_names
            result["section_entropies"] = section_entropies
            result["avg_section_entropy"] = round(
                sum(section_entropies) / len(section_entropies), 4
            ) if section_entropies else 0.0
            result["max_section_entropy"] = max(section_entropies) if section_entropies else 0.0
            result["high_entropy_sections"] = high_entropy_sections
            result["suspicious_section_names"] = suspicious_names
            result["executable_writable_sections"] = exec_write_sections
            result["section_size_anomalies"] = section_size_anomalies
            result["has_section_size_anomalies"] = bool(section_size_anomalies)

            try:
                ep_section = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                if ep_section is not None:
                    ep_name = _safe_section_name(ep_section)
                    result["entry_point_section"] = ep_name
                    result["entry_point_section_entropy"] = section_entropy_by_name.get(ep_name)
            except Exception:
                result["entry_point_section"] = None
                result["entry_point_section_entropy"] = None

            imports_count = 0
            import_names: list[str] = []
            imported_dlls: list[str] = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = ""
                    if getattr(entry, "dll", None):
                        dll_name = entry.dll.decode(errors="ignore")
                    if dll_name:
                        imported_dlls.append(dll_name)
                    for imp in getattr(entry, "imports", []) or []:
                        imports_count += 1
                        import_name = _safe_import_name(imp)
                        if import_name:
                            import_names.append(import_name)

            result["imports_count"] = imports_count
            result["import_names"] = sorted(set(import_names))
            result["imported_dlls"] = sorted(set(imported_dlls))
            result["suspicious_api_imports"] = _suspicious_api_names(import_names)
            result["suspicious_imports"] = bool(
                imports_count <= 5 or result["suspicious_api_imports"]
            )

            result["has_debug"] = hasattr(pe, "DIRECTORY_ENTRY_DEBUG")
            result["has_tls"] = hasattr(pe, "DIRECTORY_ENTRY_TLS")
            if result["has_tls"]:
                try:
                    tls_struct = pe.DIRECTORY_ENTRY_TLS.struct
                    callbacks_va = int(getattr(tls_struct, "AddressOfCallBacks", 0) or 0)
                    result["tls_callbacks"] = 1 if callbacks_va else 0
                except Exception:
                    result["tls_callbacks"] = 1

            try:
                resource_types: list[str] = []
                resource_count = 0
                if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        if entry.name:
                            resource_name = str(entry.name)
                        else:
                            resource_name = pefile.RESOURCE_TYPE.get(
                                entry.struct.Id,
                                str(entry.struct.Id),
                            )
                        resource_types.append(resource_name)
                        resource_count += 1
                result["resource_types"] = sorted(set(resource_types))
                result["resource_count"] = resource_count
                result["has_resources"] = bool(resource_count)
            except Exception:
                result["resource_types"] = []
                result["resource_count"] = 0
                result["has_resources"] = False

            try:
                overlay_offset = pe.get_overlay_data_start_offset()
                if overlay_offset is not None and overlay_offset < file_size:
                    overlay_size = max(0, file_size - int(overlay_offset))
                else:
                    overlay_size = 0
            except Exception:
                overlay_size = 0

            result["overlay_size"] = int(overlay_size)
            result["overlay_ratio"] = round((overlay_size / file_size), 4) if file_size > 0 else 0.0

            try:
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                ]
                certificate_size = int(getattr(security_dir, "Size", 0) or 0)
            except Exception:
                certificate_size = 0
            result["certificate_size"] = certificate_size
            result["has_certificate"] = certificate_size > 0

            try:
                checksum_field = int(pe.OPTIONAL_HEADER.CheckSum)
                generated_checksum = int(pe.generate_checksum())
                result["has_valid_checksum_field"] = checksum_field != 0
                result["checksum_matches"] = bool(
                    checksum_field != 0 and checksum_field == generated_checksum
                )
            except Exception:
                result["has_valid_checksum_field"] = False
                result["checksum_matches"] = None

            try:
                timestamp = int(pe.FILE_HEADER.TimeDateStamp)
                result["timestamp"] = timestamp
                if timestamp > 0:
                    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    now = datetime.now(timezone.utc)
                    result["timestamp_iso"] = dt.isoformat()
                    result["timestamp_is_future"] = dt > now
                    result["timestamp_is_very_old"] = dt.year < 2000
                else:
                    result["timestamp_is_zero"] = True
            except Exception:
                result["timestamp"] = None
                result["timestamp_iso"] = None

            result["high_entropy"] = bool(
                result["avg_section_entropy"] >= 7.0 or result["max_section_entropy"] >= 7.3
            )
            result["packed"] = bool(
                suspicious_names
                or result["high_entropy"]
                or exec_write_sections
                or imports_count <= 5
                or result["overlay_ratio"] > 0.15
                or result["suspicious_api_imports"]
                or result["tls_callbacks"] > 0
                or section_size_anomalies
            )
            return result
        finally:
            pe.close()
    except Exception as exc:
        result["parse_error"] = str(exc)
        return result
