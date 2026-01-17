import struct

# ---- Handshake message types ----
MSG_CHLO = 1  # client_id(16) | pkC_len(2) | pkC
MSG_SHLO = 2  # pkS_len(2) | pkS | cert_len(4) | cert | sig_len(2) | sig | salt(16)

# ---- Application data frame (after handshake) ----
# nonce(12) | sender_id(16) | recipient_id(16) | seq_no(8) | ct_tag(variable)

ID_LEN = 16
NONCE_LEN = 12
SEQ_LEN = 8
SALT_LEN = 16

def pack_u16(n: int) -> bytes:
    return struct.pack(">H", n)

def unpack_u16(b: bytes) -> int:
    return struct.unpack(">H", b)[0]

def pack_u32(n: int) -> bytes:
    return struct.pack(">I", n)

def unpack_u32(b: bytes) -> int:
    return struct.unpack(">I", b)[0]

def pack_u64(n: int) -> bytes:
    return struct.pack(">Q", n)

def unpack_u64(b: bytes) -> int:
    return struct.unpack(">Q", b)[0]

def frame_with_len(payload: bytes) -> bytes:
    """Prefixa o payload com 4 bytes de tamanho (big-endian)."""
    return pack_u32(len(payload)) + payload

async def read_exactly(reader, n: int) -> bytes:
    data = await reader.readexactly(n)
    return data

async def read_frame(reader) -> bytes:
    """Lê um frame length-prefixed (4 bytes)."""
    header = await read_exactly(reader, 4)
    size = unpack_u32(header)
    if size < 0 or size > 10_000_000:
        raise ValueError("Frame size inválido")
    return await read_exactly(reader, size)

def build_chlo(client_id: bytes, pk_c: bytes) -> bytes:
    if len(client_id) != ID_LEN:
        raise ValueError("client_id deve ter 16 bytes")
    return bytes([MSG_CHLO]) + client_id + pack_u16(len(pk_c)) + pk_c

def parse_chlo(payload: bytes):
    if len(payload) < 1 + ID_LEN + 2:
        raise ValueError("CHLO pequeno demais")
    if payload[0] != MSG_CHLO:
        raise ValueError("Tipo inválido (esperado CHLO)")
    client_id = payload[1:1+ID_LEN]
    pk_len = unpack_u16(payload[1+ID_LEN:1+ID_LEN+2])
    pk_c = payload[1+ID_LEN+2:1+ID_LEN+2+pk_len]
    if len(pk_c) != pk_len:
        raise ValueError("pk_C truncado")
    transcript = payload  # aqui: transcript inclui CHLO inteiro
    return client_id, pk_c, transcript

def build_shlo(pk_s: bytes, cert_pem: bytes, signature: bytes, salt: bytes) -> bytes:
    if len(salt) != SALT_LEN:
        raise ValueError("salt deve ter 16 bytes")
    out = bytearray()
    out.append(MSG_SHLO)
    out += pack_u16(len(pk_s)) + pk_s
    out += pack_u32(len(cert_pem)) + cert_pem
    out += pack_u16(len(signature)) + signature
    out += salt
    return bytes(out)

def parse_shlo(payload: bytes):
    if len(payload) < 1 + 2 + 2 + 4 + 2 + SALT_LEN:
        raise ValueError("SHLO pequeno demais")
    if payload[0] != MSG_SHLO:
        raise ValueError("Tipo inválido (esperado SHLO)")
    idx = 1

    pk_len = unpack_u16(payload[idx:idx+2]); idx += 2
    pk_s = payload[idx:idx+pk_len]; idx += pk_len
    if len(pk_s) != pk_len:
        raise ValueError("pk_S truncado")

    cert_len = unpack_u32(payload[idx:idx+4]); idx += 4
    cert_pem = payload[idx:idx+cert_len]; idx += cert_len
    if len(cert_pem) != cert_len:
        raise ValueError("cert truncado")

    sig_len = unpack_u16(payload[idx:idx+2]); idx += 2
    signature = payload[idx:idx+sig_len]; idx += sig_len
    if len(signature) != sig_len:
        raise ValueError("assinatura truncada")

    salt = payload[idx:idx+SALT_LEN]; idx += SALT_LEN
    if len(salt) != SALT_LEN:
        raise ValueError("salt truncado")

    transcript = payload  # aqui: transcript inclui SHLO inteiro (consistente nos dois lados)
    return pk_s, cert_pem, signature, salt, transcript

def build_app_frame(nonce: bytes, sender_id: bytes, recipient_id: bytes, seq_no: int, ct_tag: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce deve ter 12 bytes")
    if len(sender_id) != ID_LEN or len(recipient_id) != ID_LEN:
        raise ValueError("IDs devem ter 16 bytes")
    return nonce + sender_id + recipient_id + pack_u64(seq_no) + ct_tag

def parse_app_frame(frame: bytes):
    min_len = NONCE_LEN + ID_LEN + ID_LEN + SEQ_LEN + 16  # 16 tag mínima
    if len(frame) < min_len:
        raise ValueError("Frame de app pequeno demais")
    idx = 0
    nonce = frame[idx:idx+NONCE_LEN]; idx += NONCE_LEN
    sender_id = frame[idx:idx+ID_LEN]; idx += ID_LEN
    recipient_id = frame[idx:idx+ID_LEN]; idx += ID_LEN
    seq_no = unpack_u64(frame[idx:idx+SEQ_LEN]); idx += SEQ_LEN
    ct_tag = frame[idx:]
    aad = sender_id + recipient_id + pack_u64(seq_no)
    return nonce, sender_id, recipient_id, seq_no, ct_tag, aad
