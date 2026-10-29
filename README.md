# verifikasi integritas file dengan SHA-256 dan HMAC-SHA256

Program Python lokal buat menghitung SHA-256, menyimpan hash acuan, memverifikasi file, dan membandingkan SHA-256 dengan HMAC-SHA256. Cuma pakai pustaka standar Python, tidak perlu install paket tambahan.

## struktur proyek

```text
/
├── main.py                 # menu interaktif
├── eksperimen.py           # jalankan eksperimen langsung
├── scripts/
│   ├── __init__.py
│   ├── sha256.py           # hash, hmac, dan verifikasi
│   └── eksperimen.py       # pembuat sampel dan laporan
├── data/                   # file sampel
├── hasil/                  # manifest dan laporan
└── README.md
```

## menjalankan program

```powershell
python main.py
```

Menu yang tersedia:

1. hitung hash sha-256 file
2. simpan hash file sebagai acuan di `hasil/manifest.json`
3. verifikasi file terhadap acuan
4. buat sampel, jalankan uji integritas dan benchmark
5. hitung hmac-sha256
6. simpan baseline hmac di `hasil/manifest_hmac.json`
7. verifikasi hmac
0. keluar

Path relatif dihitung dari folder terminal, misalnya `data/asli.txt`. Menu 2 menimpa manifest lama. Menu 4 membuat ulang acuan dari `data/asli.txt`.

Eksperimen bisa juga dijalankan:

```powershell
python eksperimen.py
```

## data sampel

Semua file di `data/` adalah data sintetis. `asli.txt` adalah teks awal, sedangkan `.bin` cuma menandai sampel byte, bukan hasil enkripsi.

| file | isi |
|---|---|
| `asli.txt` | teks `Keamanan data digital` + newline, jadi acuan |
| `salinan_tanpa_perubahan.bin` | salinan identik, harusnya sesuai |
| `perubahan_1_bit.bin` | satu bit byte pertama diubah, harusnya berubah |
| `perubahan_1_huruf.bin` | `K` jadi `k`, harusnya berubah |
| `penambahan_1_byte.bin` | ditambah `!`, harusnya berubah |
| `penghapusan_1_byte.bin` | byte terakhir dihapus, harusnya berubah |
| `file_kosong.bin` | 0 byte, harusnya berubah |
| `konten_biner_256_byte.bin` | byte 0–255 buat uji konten nonteks |
| `ukuran_1KiB.bin` | 1.024 byte |
| `ukuran_100KiB.bin` | 102.400 byte |
| `ukuran_1024KiB.bin` | 1.048.576 byte |
| `ukuran_5120KiB.bin` | 5.242.880 byte |

## hasil eksperimen

| file | isi |
|---|---|
| `manifest.json` | acuan sha-256: algoritma, nama, ukuran, digest |
| `uji_integritas.csv` | tujuh skenario, status verifikasi, dan jarak bit digest |
| `benchmark_raw.csv` | 200 pengamatan: 4 ukuran × 50 ulangan |
| `benchmark_ringkasan.csv` | median, mean, stdev, min, max, throughput |
| `lingkungan.json` | versi Python, platform, seed, waktu eksperimen |
| `perbandingan_integritas.csv` | hasil sha-256 vs hmac per skenario |
| `benchmark_perbandingan_raw.csv` | waktu mentah sha-256 vs hmac |
| `benchmark_perbandingan_ringkasan.csv` | ringkasan waktu kedua metode |

Durasi benchmark termasuk pembacaan file. Cache dan proses lain tidak dikendalikan, jadi hasil bisa beda antar mesin atau saat dijalankan ulang. Kolom `beda_bit` adalah jarak Hamming antar digest SHA-256, bukan jumlah bit yang berubah di file sumber.

## catatan hmac

SHA-256 yang cocok cuma menunjukkan isi file sama dengan acuan, bukan siapa pembuatnya, karena penyerang bisa mengganti file sekaligus manifest. HMAC menutup celah itu selama kuncinya tidak bocor.

Sebelum pakai menu 5–7, set `SHA256_HMAC_KEY`:

```powershell
$env:SHA256_HMAC_KEY = 'kunci-acak-rahasia-milik-anda'
```

Jangan simpan kunci produksi di source code, manifest, atau ZIP. Eksperimen memakai kunci demo publik khusus pengujian, jadi jangan dipakai buat autentikasi nyata.

Menjalankan eksperimen menimpa file sampel dan hasil dengan nama yang sama. Salin dulu kalau mau menyimpan keluaran sebelumnya.
