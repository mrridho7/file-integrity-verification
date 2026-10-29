import hashlib
import hmac
import json
from pathlib import Path

UKURAN_BLOK = 1024 * 1024

# hitung sha-256 sambil baca file per blok
def hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as file_handle:

        while potongan := file_handle.read(UKURAN_BLOK):
            digest.update(potongan)
    return digest.hexdigest()

# sv acuan sha-256 ke manifest json
def save_baseline(path, manifest):
    file_path = Path(path)
    baseline = {
        'algorithm': 'SHA-256',
        'filename': file_path.name,
        'size_bytes': file_path.stat().st_size,
        'sha256': hash_file(file_path),
    }
    Path(manifest).write_text(json.dumps(baseline, indent=2), encoding='utf-8')
    return baseline

# bandingin file sama manifest, balikin (cocok, hash aktual, hash acuan)
def verify_file(path, manifest):
    baseline = json.loads(Path(manifest).read_text(encoding='utf-8'))
    expected_hash = baseline.get('sha256')
    if (
        baseline.get('algorithm') != 'SHA-256'
        or not isinstance(expected_hash, str)
        or len(expected_hash) != 64
    ):
        raise ValueError('Format manifest tidak valid')
    actual_hash = hash_file(path)
    return hmac.compare_digest(actual_hash, expected_hash), actual_hash, expected_hash

# hmac-sha256
def hmac_file(path, key):
    # kunci harus bytes dan gak boleh kosong
    if not isinstance(key, bytes) or not key:
        raise ValueError('Kunci HMAC wajib berupa bytes nonkosong')
    mac = hmac.new(key, digestmod=hashlib.sha256)
    with Path(path).open('rb') as fh:
        while chunk := fh.read(UKURAN_BLOK):
            mac.update(chunk)
    return mac.hexdigest()

# sv tag hmac sebagai acuan
def save_hmac_baseline(path, manifest, key):
    file_path = Path(path)
    baseline = {'algorithm': 'HMAC-SHA256', 'filename': file_path.name,
                'size_bytes': file_path.stat().st_size, 'tag': hmac_file(file_path, key)}
    Path(manifest).write_text(json.dumps(baseline, indent=2), encoding='utf-8')
    return baseline

# verifikasi tag hmac
def verify_hmac_file(path, manifest, key):
    baseline = json.loads(Path(manifest).read_text(encoding='utf-8'))
    tag = baseline.get('tag')
    # tag wajib 64 karakter, cek bentuknya sebelum dipakai
    if baseline.get('algorithm') != 'HMAC-SHA256' or not isinstance(tag, str) or len(tag) != 64:
        raise ValueError('Format manifest HMAC tidak valid')
    try:
        bytes.fromhex(tag)
    except ValueError as exc:
        raise ValueError('Tag HMAC bukan heksadesimal') from exc
    actual = hmac_file(path, key)
    return hmac.compare_digest(actual, tag), actual, tag
