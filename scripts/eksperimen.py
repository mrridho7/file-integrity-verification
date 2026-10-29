import csv
import json
import platform
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .sha256 import hash_file, save_baseline, verify_file, hmac_file, save_hmac_baseline, verify_hmac_file

# alur eksperimen: uji integritas, benchmark sha-256, lalu bandingin sama hmac
def run_eksperimen():
    ROOT = Path(__file__).resolve().parent.parent
    DATA = ROOT / 'data'
    HASIL = ROOT / 'hasil'
    DATA.mkdir(exist_ok=True)
    HASIL.mkdir(exist_ok=True)

    # empat ukuran file dan 50 ulangan
    UKURAN = [1024, 102400, 1048576, 5242880]
    ULANGAN = 50
    SEED = 42
    # seed bikin file acak bisa dibuat ulang persis
    rng = random.Random(SEED)

    # bikin file asli dan sv hash acuannya
    asli = b'Keamanan data digital\n'
    file_asli = DATA / 'asli.txt'
    file_asli.write_bytes(asli)
    manifest = HASIL / 'manifest.json'
    save_baseline(file_asli, manifest)
    hash_acuan = hash_file(file_asli)

    # tiap skenario: (nama file, isi, harusnya masih cocok atau enggak)
    skenario = [
        ('salinan_tanpa_perubahan', asli, True),
        ('perubahan_1_bit', bytes([asli[0] ^ 1]) + asli[1:], False),
        ('perubahan_1_huruf', b'keamanan data digital\n', False),
        ('penambahan_1_byte', asli + b'!', False),
        ('penghapusan_1_byte', asli[:-1], False),
        ('file_kosong', b'', False),
        ('konten_biner_256_byte', bytes(range(256)), False),
    ]

    integritas = []
    for nama, isi, diharapkan_sesuai in skenario:
        # tulis sampel lalu cocokkan sama manifest acuan
        file_uji = DATA / f'{nama}.bin'
        file_uji.write_bytes(isi)
        sesuai, hash_aktual, _ = verify_file(file_uji, manifest)
        # jarak bit dihitung pada digest, bukan pada byte file sumber
        beda_bit = sum(
            (a ^ b).bit_count()
            for a, b in zip(bytes.fromhex(hash_acuan), bytes.fromhex(hash_aktual))
        )
        integritas.append({
            'skenario': nama,
            'ukuran_byte': len(isi),
            'sesuai_acuan': sesuai,
            'harapan_sesuai': diharapkan_sesuai,
            'lulus': sesuai == diharapkan_sesuai,
            'beda_bit': beda_bit,
            'hash_sha256': hash_aktual,
        })

    # sv hasil uji integritas ke csv
    with (HASIL / 'uji_integritas.csv').open('w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=integritas[0].keys())
        writer.writeheader()
        writer.writerows(integritas)

    # ukur waktu hashing tiap ukuran file, ulang 50 kali biar bisa diambil median
    pengukuran = []
    ringkasan = []
    for ukuran in UKURAN:
        file_uji = DATA / f'ukuran_{ukuran // 1024}KiB.bin'
        file_uji.write_bytes(rng.randbytes(ukuran))
        waktu = []

        # perf_counter_ns lebih presisi buat durasi pendek dibanding time.time
        for nomor in range(1, ULANGAN + 1):
            mulai = time.perf_counter_ns()
            hash_file(file_uji)
            durasi_ms = (time.perf_counter_ns() - mulai) / 1_000_000
            waktu.append(durasi_ms)
            pengukuran.append({
                'ukuran_byte': ukuran,
                'ulangan': nomor,
                'waktu_ms': round(durasi_ms, 6),
            })

        # median dipakai buat throughput karena lebih tahan outlier
        median = statistics.median(waktu)
        ringkasan.append({
            'ukuran_byte': ukuran,
            'ulangan': ULANGAN,
            'median_ms': round(median, 4),
            'mean_ms': round(statistics.mean(waktu), 4),
            'stdev_ms': round(statistics.stdev(waktu), 4),
            'min_ms': round(min(waktu), 4),
            'max_ms': round(max(waktu), 4),
            # ukuran MiB dibagi median waktu dalam detik
            'throughput_mib_s': round((ukuran / 1048576) / (median / 1000), 2),
        })

    # dua file benchmark: data mentah per ulangan dan ringkasannya
    for nama, data in [('benchmark_raw.csv', pengukuran),
                       ('benchmark_ringkasan.csv', ringkasan)]:
        with (HASIL / nama).open('w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

    # catat lingkungan supaya hasil benchmark gampang dibandingin antar mesin
    lingkungan = {
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'processor': platform.processor() or 'tidak terdeteksi',
        'repetisi_per_ukuran': ULANGAN,
        'seed': SEED,
        'pengukuran': 'waktu total hashing termasuk pembacaan file; cache tidak dikendalikan',
        'waktu_utc': datetime.now(timezone.utc).isoformat(),
    }
    (HASIL / 'lingkungan.json').write_text(json.dumps(lingkungan, indent=2), encoding='utf-8')

    # perbandingan sha-256 vs hmac pakai sampel dan jumlah ulangan yang sama
    key = b'KUNCI-DEMO-UNTUK-EKSPERIMEN-SAJA-2026'
    hmac_manifest = HASIL / 'manifest_hmac_demo.json'
    save_hmac_baseline(file_asli, hmac_manifest, key)
    perbandingan_integritas = []
    for nama, isi, expected in skenario:
        path = DATA / f'{nama}.bin'
        # tiap skenario dicek dua kali: pakai sha-256 dan pakai hmac
        ok_sha, _, _ = verify_file(path, manifest)
        ok_hmac, _, _ = verify_hmac_file(path, hmac_manifest, key)
        perbandingan_integritas.append({'skenario': nama, 'sha256_sesuai': ok_sha,
            'hmac_sesuai': ok_hmac, 'harapan_sesuai': expected,
            'lulus': ok_sha == expected and ok_hmac == expected})

    # di sini penyerang dianggap bisa ganti file sekaligus manifest sha-256,
    # tapi tidak pegang kunci hmac jadi tag yang sah tidak bisa dibikin ulang
    manipulasi = DATA / 'manipulasi_demo.bin'
    manipulasi.write_bytes(b'konten diganti oleh penyerang')
    forged_manifest = HASIL / 'manifest_sha256_dipalsukan_demo.json'
    save_baseline(manipulasi, forged_manifest)
    sha_forged, _, _ = verify_file(manipulasi, forged_manifest)
    hmac_forged, _, _ = verify_hmac_file(manipulasi, hmac_manifest, key)
    # kunci salah juga harus ditolak, bukan cuma file yang beda
    wrong_key, _, _ = verify_hmac_file(file_asli, hmac_manifest, b'KUNCI-SALAH')
    perbandingan_integritas.extend([
        {'skenario':'file_dan_manifest_sha256_diganti', 'sha256_sesuai':sha_forged,
         'hmac_sesuai':hmac_forged, 'harapan_sesuai':False,
         'lulus':sha_forged and not hmac_forged},
        {'skenario':'kunci_hmac_salah', 'sha256_sesuai':'tidak berlaku',
         'hmac_sesuai':wrong_key, 'harapan_sesuai':False, 'lulus':not wrong_key},
    ])
    # tulis hasil perbandingan ke csv
    with (HASIL / 'perbandingan_integritas.csv').open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=perbandingan_integritas[0].keys())
        writer.writeheader(); writer.writerows(perbandingan_integritas)

    # benchmark berpasangan, urutan metode dibalik tiap ulangan genap
    # biar efek cache atau panas mesin gak selalu jatuh ke metode yang sama
    benchmark = []
    for ukuran in UKURAN:
        path = DATA / f'ukuran_{ukuran // 1024}KiB.bin'
        for nomor in range(1, ULANGAN + 1):
            order = [('SHA-256',hash_file), ('HMAC-SHA256',lambda x:hmac_file(x,key))]
            if nomor % 2 == 0: order.reverse()
            for metode, fn in order:
                # catat waktu tiap metode di file yang sama, satu per satu
                start = time.perf_counter_ns()
                fn(path)
                elapsed = (time.perf_counter_ns()-start)/1_000_000
                benchmark.append({'metode':metode,'ukuran_byte':ukuran,
                                  'ulangan':nomor,'waktu_ms':round(elapsed,6)})
    # sv semua pengukuran mentah perbandingan
    with (HASIL / 'benchmark_perbandingan_raw.csv').open('w',newline='',encoding='utf-8') as fh:
        writer=csv.DictWriter(fh,fieldnames=benchmark[0].keys());writer.writeheader();writer.writerows(benchmark)
    # ringkas per metode dan ukuran file pakai median, mean, dan stdev
    summary=[]
    for ukuran in UKURAN:
        for metode in ['SHA-256','HMAC-SHA256']:
            vals=[r['waktu_ms'] for r in benchmark if r['ukuran_byte']==ukuran and r['metode']==metode]
            summary.append({'metode':metode,'ukuran_byte':ukuran,'ulangan':len(vals),
                            'median_ms':round(statistics.median(vals),4),
                            'mean_ms':round(statistics.mean(vals),4),
                            'stdev_ms':round(statistics.stdev(vals),4)})
    with (HASIL / 'benchmark_perbandingan_ringkasan.csv').open('w',newline='',encoding='utf-8') as fh:
        writer=csv.DictWriter(fh,fieldnames=summary[0].keys());writer.writeheader();writer.writerows(summary)

    print('Perbandingan integritas:',sum(r['lulus'] for r in perbandingan_integritas),'/',len(perbandingan_integritas))
    print('Benchmark perbandingan:',len(benchmark),'pengukuran')
    print(f'Integritas: {len(integritas)}/{len(integritas)} skenario lulus')
    print(f'Benchmark: {len(pengukuran)} pengukuran')
    for baris in ringkasan:
        print(f"{baris['ukuran_byte']:>8} byte: median {baris['median_ms']} ms")
