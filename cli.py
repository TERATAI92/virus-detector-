import argparse
import json
import os
import sys

from scanner import scan_file


def pretty_print(res):
    print("=" * 60)
    print("File     :", res.get("file"))

    if res.get("error"):
        print("Error    :", res.get("error"))

    if res.get("size") is not None:
        print("Ukuran   :", res.get("size"), "bytes")

    hashes = res.get("hashes")
    if hashes:
        print("MD5      :", hashes.get("md5"))
        print("SHA1     :", hashes.get("sha1"))
        print("SHA256   :", hashes.get("sha256"))

    if res.get("entropy") is not None:
        print("Entropy  :", res.get("entropy"))

    print("Score    :", res.get("score", 0))
    print("Verdict  :", res.get("verdict"))

    detections = res.get("detections", [])
    if detections:
        print("\nDeteksi:")
        for d in detections:
            print("-", d)
    else:
        print("\nDeteksi  : tidak ada deteksi lokal")

    vt = res.get("virustotal")
    if vt:
        print("\nVirusTotal:")
        print(json.dumps(vt, indent=2, ensure_ascii=False))

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Deteksi virus/file mencurigakan berbasis Python"
    )
    parser.add_argument("path", help="Path file yang akan discan")
    parser.add_argument(
        "--vt-key",
        default=os.environ.get("VT_API_KEY", ""),
        help="API key VirusTotal, bisa juga lewat env VT_API_KEY"
    )
    parser.add_argument(
        "--rules",
        default="yara_rules",
        help="Folder aturan YARA"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output dalam format JSON"
    )

    args = parser.parse_args()

    result = scan_file(
        args.path,
        vt_api_key=args.vt_key or None,
        rules_dir=args.rules
    )

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        pretty_print(result)

    verdict = result.get("verdict", "")
    if verdict.startswith("CLEAN"):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
