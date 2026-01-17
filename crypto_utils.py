import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    Encoding, PublicFormat
)
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

# ---- ECDHE (P-256) ----
def ecdhe_generate_keypair():
    sk = ec.generate_private_key(ec.SECP256R1())
    pk_bytes = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return sk, pk_bytes

def ecdhe_load_peer_public(pk_bytes: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_bytes)

def ecdhe_shared_secret(sk_local, pk_peer_bytes: bytes) -> bytes:
    peer_pk = ecdhe_load_peer_public(pk_peer_bytes)
    return sk_local.exchange(ec.ECDH(), peer_pk)

# ---- RSA signature (PSS + SHA256) ----
def rsa_sign_pss_sha256(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def rsa_verify_pss_sha256(public_key, signature: bytes, data: bytes) -> None:
    public_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# ---- HKDF (Extract + Expand) (HMAC-SHA256) ----
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()  # PRK (32 bytes)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # HKDF-Expand basic (RFC 5869)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        h = hmac.HMAC(prk, hashes.SHA256())
        h.update(t + info + bytes([counter]))
        t = h.finalize()
        okm += t
        counter += 1
        if counter > 255:
            raise ValueError("HKDF counter overflow")
    return okm[:length]

def derive_session_keys(z: bytes, salt: bytes) -> tuple[bytes, bytes]:
    prk = hkdf_extract(salt, z)
    key_c2s = hkdf_expand(prk, b"c2s", 16)  # AES-128
    key_s2c = hkdf_expand(prk, b"s2c", 16)
    return key_c2s, key_s2c

# ---- AES-128-GCM ----
def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)  # retorna ct||tag

def aead_decrypt(key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct_tag, aad)

# ---- Cert loading / pinning ----
def load_rsa_private_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    return load_pem_private_key(data, password=None)

def load_cert_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def cert_public_key_from_pem(cert_pem: bytes):
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key()

# ---- Nonce helper ----
@dataclass
class NonceStrategy:
    prefix: bytes  # 4 bytes

    @staticmethod
    def new() -> "NonceStrategy":
        return NonceStrategy(prefix=os.urandom(4))

    def make(self, seq_no: int) -> bytes:
        # 4B prefix + 8B seq_no = 12B
        return self.prefix + seq_no.to_bytes(8, "big", signed=False)
