import json
import os
from pathlib import Path

from scripts.sha256 import hash_file, save_baseline, verify_file, hmac_file, save_hmac_baseline, verify_hmac_file
from scripts.eksperimen import run_eksperimen

# manifest sha-256 jadi acuan verifikasi, manifest hmac nanti dibuat di folder yang sama
MANIFEST_PATH = Path(__file__).resolve().parent / "hasil" / "manifest.json"

def main():
    while True:
        # daftar menu, nomor 5-7 khusus hmac
        print("\nVerifikasi Integritas File dengan SHA-256")
        print("-" * 40)
        print("1. Hitung hash file")
        print("2. Simpan hash acuan")
        print("3. Verifikasi file")
        print("4. Jalankan eksperimen")
        print("5. Hitung HMAC-SHA256")
        print("6. Simpan baseline HMAC")
        print("7. Verifikasi HMAC")
        print("0. Keluar")
        pilihan = input("Pilih menu: ").strip()

        # 0 keluar mode
        if pilihan == "0":
            break
        if pilihan not in {"1", "2", "3", "4", "5", "6", "7"}:
            print("Pilihan tidak tersedia")
            continue

        try:
            if pilihan == "4":
                run_eksperimen()
                continue

            file_path = input("Masukkan path file: ").strip().strip('"')
            
            # menu 5-7 pakai hmac
            if pilihan in {"5", "6", "7"}:
                key_text = os.environ.get("SHA256_HMAC_KEY")
                if not key_text:
                    raise ValueError("Set SHA256_HMAC_KEY di environment terlebih dahulu")
                key = key_text.encode("utf-8")
                hmac_manifest = MANIFEST_PATH.with_name("manifest_hmac.json")
                if pilihan == "5":
                    print("HMAC-SHA256:", hmac_file(file_path, key))
                elif pilihan == "6":
                    save_hmac_baseline(file_path, hmac_manifest, key)
                    print("Manifest HMAC disimpan:", hmac_manifest)
                else:
                    cocok, _, _ = verify_hmac_file(file_path, hmac_manifest, key)
                    print("Status:", "SESUAI" if cocok else "BERUBAH")
            # menu 1 cuma hitung hash, gak nyentuh manifest
            elif pilihan == "1":
                print("SHA-256:", hash_file(file_path))
            # menu 2 bikin folder hasil kalau belum ada, lalu sv acuan
            elif pilihan == "2":
                MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
                baseline = save_baseline(file_path, MANIFEST_PATH)
                print("Hash acuan disimpan:", MANIFEST_PATH)
                print("SHA-256:", baseline["sha256"])
            # menu 3 bandingin file sekarang sama hash acuan
            elif pilihan == "3":
                cocok, actual_hash, expected_hash = verify_file(file_path, MANIFEST_PATH)
                print("Status:", "SESUAI" if cocok else "BERUBAH")
                print("Hash file :", actual_hash)
                print("Hash acuan:", expected_hash)

        except (OSError, ValueError, json.JSONDecodeError) as error:
            print("Gagal:", error)

if __name__ == "__main__":
    main()