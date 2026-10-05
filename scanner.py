import os
import re
import math
import json
import hashlib
import zipfile
from pathlib import Path
from collections import Counter

# =========================================================
# Dependensi eksternal opsional
# =========================================================
try:
    import requests
except Exception:
    requests = None

try:
    import yara
except Exception:
    yara = None

try:
    # Androguard versi baru
    from androguard.core.apk import APK
except Exception:
    try:
        # Androguard versi lama
        from androguard.core.bytecodes.apk import APK
    except Exception:
        APK = None


# =========================================================
# Konfigurasi
# =========================================================
MAX_SCAN_BYTES = 20 * 1024 * 1024  # batas baca 20 MB agar aman di HP

# Contoh blacklist lokal.
# Hash di bawah adalah EICAR test file, file uji antivirus yang aman.
BLACKLIST_HASHES = {
    "md5": {
        "44d88612fea8a8f36de82e1278abb02f"
    },
    "sha1": {
        "3395856ce81f2b7382dee72602f798b642f14140"
    },
    "sha256": {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    }
}

# Pola string yang sering muncul pada file berbahaya.
# Ini heuristik sederhana, bisa false positive.
SUSPICIOUS_PATTERNS = [
    r"(?i)eicar-standard-antivirus-test-file",
    r"(?i)powershell\s+.*-(e|enc|encodedcommand)\b",
    r"(?i)cmd\.exe\s+/c",
    r"(?i)certutil\s+.*-urlcache",
    r"(?i)bitsadmin\s+/transfer",
    r"(?i)mshta\s+(vbscript|javascript|http)",
    r"(?i)reg\s+add\s+.*\\run",
    r"(?i)/system/bin/su",
    r"(?i)Runtime;->exec",
    r"(?i)Landroid/telephony/TelephonyManager;->getDeviceId",
    r"(?i)Lcom/android/internal/telephony/SmsManager;->sendTextMessage",
    r"(?i)base64[_-]?decode",
    r"(?i)eval\s*\(",
]

COMPILED_PATTERNS = [(p, re.compile(p)) for p in SUSPICIOUS_PATTERNS]

SUSPICIOUS_ZIP_EXTENSIONS = (
    ".dex", ".so", ".jar", ".apk", ".bin",
    ".sh", ".pyc", ".elf", ".exe", ".dll"
)


# =========================================================
# Fungsi dasar
# =========================================================
def calculate_hashes(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def calculate_entropy(data: bytes) -> float:
    """
    Entropi tinggi sering menandakan file dikompresi/dienkripsi.
    Tidak selalu berbahaya, tapi bisa jadi indikasi packing.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def check_blacklist(hashes):
    hits = []
    for algo, value in hashes.items():
        if value in BLACKLIST_HASHES.get(algo, set()):
            hits.append(f"{algo}:{value}")
    return hits


# =========================================================
# Pemeriksaan ZIP/APK
# =========================================================
def scan_zip(path):
    if not zipfile.is_zipfile(path):
        return None

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            suspicious = []

            for name in names:
                low = name.lower()
                if low.endswith(SUSPICIOUS_ZIP_EXTENSIONS):
                    suspicious.append(name)

            is_apk = (
                any(name == "AndroidManifest.xml" for name in names)
                or str(path).lower().endswith(".apk")
            )

            return {
                "is_zip": True,
                "is_apk": is_apk,
                "entries": len(names),
                "suspicious_entries": suspicious[:50],
            }
    except Exception as e:
        return {"error": str(e)}


def scan_apk_metadata(path):
    """
    Opsional: hanya aktif jika androguard terpasang.
    """
    if APK is None:
        return None

    if not str(path).lower().endswith(".apk"):
        return None

    try:
        a = APK(str(path))
        perms = a.get_permissions()

        high = []
        risky = []

        for p in perms:
            pu = p.upper()

            if any(x in pu for x in (
                "REQUEST_INSTALL_PACKAGES",
                "BIND_ACCESSIBILITY_SERVICE",
                "BIND_DEVICE_ADMIN",
                "WRITE_SECURE_SETTINGS",
            )):
                high.append(p)
            elif any(x in pu for x in (
                "SEND_SMS",
                "READ_SMS",
                "RECEIVE_SMS",
                "READ_CONTACTS",
                "ACCESS_FINE_LOCATION",
                "CAMERA",
                "RECORD_AUDIO",
                "READ_PHONE_STATE",
                "WRITE_SETTINGS",
            )):
                risky.append(p)

        return {
            "package": a.get_package(),
            "app_name": a.get_app_name(),
            "permissions": perms,
            "high_risk_permissions": high,
            "risky_permissions": risky,
        }
    except Exception as e:
        return {"error": str(e)}


# =========================================================
# Pemeriksaan YARA
# =========================================================
def scan_yara(path, rules_dir):
    if yara is None:
        return {
            "available": False,
            "matches": [],
            "message": "Modul yara-python tidak terpasang."
        }

    rd = Path(rules_dir)
    if not rd.exists():
        return {
            "available": False,
            "matches": [],
            "message": f"Folder rules {rules_dir} tidak ditemukan."
        }

    filepaths = {}
    for i, rulefile in enumerate(sorted(rd.glob("*.yar"))):
        key = f"rule_{i}_{rulefile.stem}"
        filepaths[key] = str(rulefile)

    if not filepaths:
        return {
            "available": False,
            "matches": [],
            "message": "Tidak ada file .yar di folder rules."
        }

    try:
        rules = yara.compile(filepaths=filepaths)
        matches = rules.match(str(path), timeout=60)
        return {
            "available": True,
            "matches": [m.rule for m in matches],
        }
    except Exception as e:
        return {
            "available": False,
            "matches": [],
            "error": str(e),
        }


# =========================================================
# VirusTotal lookup berdasarkan hash
# =========================================================
def virustotal_lookup(sha256, api_key):
    """
    Mengirim hash SHA256 ke VirusTotal, bukan upload file.
    Lebih privat, tetapi hanya bekerja jika file sudah pernah dianalisis VT.
    """
    if not api_key:
        return None

    if requests is None:
        return {"error": "Modul requests belum terpasang."}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": api_key.strip()
    }

    try:
        r = requests.get(url, headers=headers, timeout=30)

        if r.status_code == 404:
            return {
                "found": False,
                "message": "Hash belum ada di VirusTotal."
            }

        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}

        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "found": True,
            "stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception as e:
        return {"error": str(e)}


# =========================================================
# Scanner utama
# =========================================================
def scan_file(path, vt_api_key=None, rules_dir="yara_rules", read_limit=MAX_SCAN_BYTES):
    p = Path(path)

    result = {
        "file": str(p),
        "exists": p.exists(),
        "modules": {
            "requests": requests is not None,
            "yara": yara is not None,
            "androguard": APK is not None,
        },
        "detections": [],
        "score": 0,
    }

    if not result["exists"]:
        result["error"] = "File tidak ditemukan"
        return result

    if not p.is_file():
        result["error"] = "Path bukan file"
        return result

    try:
        size = p.stat().st_size
    except Exception as e:
        result["error"] = f"Gagal stat file: {e}"
        return result

    result["size"] = size
    result["partial_scan"] = size > read_limit

    try:
        hashes = calculate_hashes(path)
    except Exception as e:
        result["error"] = f"Gagal membaca file: {e}"
        return result

    result["hashes"] = hashes

    detections = []
    score = 0

    # 1. Cek blacklist hash lokal
    hits = check_blacklist(hashes)
    if hits:
        detections.append("Hash cocok dengan daftar hitam lokal: " + ", ".join(hits))
        score += 100

    # 2. Baca sebagian file untuk heuristik
    try:
        with open(path, "rb") as f:
            data = f.read(read_limit)
    except Exception as e:
        result["error"] = f"Gagal membaca file: {e}"
        return result

    # 3. Entropi
    entropy = calculate_entropy(data)
    result["entropy"] = round(entropy, 3)

    if entropy > 7.4:
        detections.append("Entropi sangat tinggi: kemungkinan file dikompresi/dienkripsi/packed.")
        score += 10
    elif entropy > 6.8:
        detections.append("Entropi tinggi.")
        score += 5

    # 4. Cari string mencurigakan
    text = data.decode("utf-8", "ignore")
    found_patterns = set()

    for original_pattern, rx in COMPILED_PATTERNS:
        if rx.search(text):
            found_patterns.add(original_pattern)

    if found_patterns:
        detections.append(
            "Pola/string mencurigakan: " + ", ".join(sorted(found_patterns))
        )
        score += min(50, 10 * len(found_patterns))

    # 5. Cek struktur ZIP/APK
    zip_info = scan_zip(path)
    if zip_info:
        result["zip"] = zip_info

        if zip_info.get("is_apk"):
            score += 5

        suspicious_entries = zip_info.get("suspicious_entries", [])
        if suspicious_entries:
            detections.append(
                "File arsip/APK mengandung file berpotensi dieksekusi: "
                + ", ".join(suspicious_entries[:10])
            )
            score += min(30, 3 * len(suspicious_entries))

    # 6. Analisis APK dengan androguard jika tersedia
    apk_meta = scan_apk_metadata(path)
    if apk_meta:
        result["apk_metadata"] = apk_meta

        if not apk_meta.get("error"):
            high = apk_meta.get("high_risk_permissions", [])
            risky = apk_meta.get("risky_permissions", [])

            if high:
                detections.append(
                    "Izin APK berisiko tinggi: " + ", ".join(high)
                )
                score += min(40, 20 * len(high))
            elif len(risky) >= 4:
                detections.append(
                    "Banyak izin APK yang sensitif: " + ", ".join(risky[:10])
                )
                score += 15

    # 7. YARA rules
    yara_info = scan_yara(path, rules_dir)
    result["yara"] = yara_info

    if yara_info.get("matches"):
        detections.append("YARA match: " + ", ".join(yara_info["matches"]))
        score += 40

    # 8. VirusTotal
    vt_info = None
    if vt_api_key:
        vt_info = virustotal_lookup(hashes["sha256"], vt_api_key)
        result["virustotal"] = vt_info

        if vt_info and vt_info.get("found"):
            mal = vt_info.get("malicious", 0)
            susp = vt_info.get("suspicious", 0)

            if mal >= 5:
                detections.append(f"VirusTotal: {mal} engine mendeteksi malicious.")
                score += 80
            elif mal >= 1 or susp >= 1:
                detections.append(f"VirusTotal: {mal} malicious, {susp} suspicious.")
                score += 40
        elif vt_info and vt_info.get("error"):
            detections.append("VirusTotal error: " + vt_info["error"])

    result["detections"] = detections

    score = max(0, min(100, score))
    result["score"] = score

    vt_found = bool(vt_info and vt_info.get("found"))
    mal = vt_info.get("malicious", 0) if vt_found else 0
    susp = vt_info.get("suspicious", 0) if vt_found else 0

    if score >= 80 or mal >= 10:
        verdict = "MALICIOUS"
    elif score >= 35 or mal >= 1 or susp >= 1:
        verdict = "SUSPICIOUS"
    elif vt_found and mal == 0 and susp == 0 and score < 20:
        verdict = "CLEAN"
    elif score < 10:
        verdict = "UNKNOWN/CLEAN"
    else:
        verdict = "LOW_RISK"

    result["verdict"] = verdict
    return result
