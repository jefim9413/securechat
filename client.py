import asyncio
import sys
import uuid
from dataclasses import dataclass

from protocol import (
    frame_with_len, read_frame, build_chlo, parse_shlo,
    build_app_frame, parse_app_frame
)
from crypto_utils import (
    ecdhe_generate_keypair, ecdhe_shared_secret,
    cert_public_key_from_pem, rsa_verify_pss_sha256,
    derive_session_keys, aead_encrypt, aead_decrypt, NonceStrategy
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888
PINNED_CERT_PATH = "server_cert.pem"

@dataclass
class ClientState:
    client_id: bytes
    key_c2s: bytes
    key_s2c: bytes
    seq_send: int
    seq_recv: int
    nonce_send: NonceStrategy

def hex_id(cid: bytes) -> str:
    return cid.hex()

def parse_hex_16(s: str) -> bytes:
    b = bytes.fromhex(s)
    if len(b) != 16:
        raise ValueError("ID deve ter 16 bytes (32 hex chars)")
    return b

async def handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_id: bytes) -> ClientState:
    # ---- client ephemeral ECDHE ----
    sk_c, pk_c = ecdhe_generate_keypair()

    chlo = build_chlo(client_id, pk_c)
    writer.write(frame_with_len(chlo))
    await writer.drain()

    shlo = await read_frame(reader)
    pk_s, cert_pem, signature, salt, shlo_transcript = parse_shlo(shlo)

    # ---- cert pinning ----
    with open(PINNED_CERT_PATH, "rb") as f:
        pinned = f.read()
    if pinned != cert_pem:
        raise ValueError("Certificado do servidor não confere (pinning falhou)")

    # ---- verify RSA signature ----
    transcript = chlo  # deve bater com o lado do servidor
    to_verify = pk_s + client_id + transcript + salt

    pub = cert_public_key_from_pem(cert_pem)
    rsa_verify_pss_sha256(pub, signature, to_verify)

    # ---- derive keys ----
    z = ecdhe_shared_secret(sk_c, pk_s)
    key_c2s, key_s2c = derive_session_keys(z, salt)

    return ClientState(
        client_id=client_id,
        key_c2s=key_c2s,
        key_s2c=key_s2c,
        seq_send=0,
        seq_recv=-1,
        nonce_send=NonceStrategy.new(),
    )

async def recv_loop(reader, state):
    try:
        while True:
            frame = await read_frame(reader)
            nonce, sender_id, recipient_id, seq_no, ct_tag, aad = parse_app_frame(frame)

            if seq_no <= state.seq_recv:
                print("\n[!] Replay detectado (cliente)")
                continue

            plaintext = aead_decrypt(state.key_s2c, nonce, ct_tag, aad)
            state.seq_recv = seq_no

            msg = plaintext.decode("utf-8", errors="replace")
            print(f"\n<< de {sender_id.hex()}: {msg}")
            print(">> ", end="", flush=True)

    except asyncio.IncompleteReadError:
        print("\n[-] Conexão encerrada pelo servidor.")

async def send_loop(writer: asyncio.StreamWriter, state: ClientState, recipient_id: bytes):
    loop = asyncio.get_running_loop()
    while True:
        # input sem bloquear o event loop
        msg = await loop.run_in_executor(None, lambda: input(">> "))
        if msg.strip().lower() in {"/quit", "/exit"}:
            writer.close()
            await writer.wait_closed()
            return

        plaintext = msg.encode("utf-8")
        seq = state.seq_send
        nonce = state.nonce_send.make(seq)
        aad = state.client_id + recipient_id + seq.to_bytes(8, "big")

        ct_tag = aead_encrypt(state.key_c2s, nonce, plaintext, aad)
        frame = build_app_frame(nonce, state.client_id, recipient_id, seq, ct_tag)

        writer.write(frame_with_len(frame))
        await writer.drain()

        state.seq_send += 1

async def main():
    host = SERVER_HOST
    port = SERVER_PORT

    # client_id fixo desta execução
    client_id = uuid.uuid4().bytes  # 16 bytes
    print(f"Seu client_id: {hex_id(client_id)}")

    # destinatário
    rec_hex = input("Digite o recipient_id (32 hex chars) do outro cliente: ").strip()
    recipient_id = parse_hex_16(rec_hex)

    reader, writer = await asyncio.open_connection(host, port)
    state = await handshake(reader, writer, client_id)

    print("[+] Handshake OK. Digite mensagens. (/quit para sair)")

    recv_task = asyncio.create_task(recv_loop(reader, state))
    send_task = asyncio.create_task(send_loop(writer, state, recipient_id))

    done, pending = await asyncio.wait(
        [recv_task, send_task],
        return_when=asyncio.FIRST_COMPLETED
    )

    # cancela a task que sobrou
    for task in pending:
        task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
