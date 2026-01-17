import asyncio
import os
from dataclasses import dataclass
from typing import Dict, Optional

from protocol import (
    frame_with_len, read_frame, build_shlo, parse_chlo, parse_app_frame,
    build_app_frame
)
from crypto_utils import (
    ecdhe_generate_keypair, ecdhe_shared_secret,
    rsa_sign_pss_sha256, load_rsa_private_key, load_cert_pem, cert_public_key_from_pem,
    derive_session_keys, aead_decrypt, aead_encrypt, NonceStrategy
)

@dataclass
class Session:
    client_id: bytes
    writer: asyncio.StreamWriter
    key_c2s: bytes
    key_s2c: bytes
    seq_recv: int
    seq_send: int
    nonce_send: NonceStrategy

sessions: Dict[bytes, Session] = {}
sessions_lock = asyncio.Lock()

SERVER_KEY_PATH = "server_key.pem"
SERVER_CERT_PATH = "server_cert.pem"
HOST = "0.0.0.0"
PORT = 8888

def hex_id(cid: bytes) -> str:
    return cid.hex()

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    client_id = None
    try:
        # ---- Handshake: receive CHLO ----
        chlo = await read_frame(reader)
        client_id, pk_c, chlo_transcript = parse_chlo(chlo)

        # ---- Server generates ephemeral ECDHE + salt ----
        sk_s, pk_s = ecdhe_generate_keypair()
        salt = os.urandom(16)

        # transcript: simplest = CHLO bytes + pk_s + salt (also SHLO bytes will be included on client side parse)
        # We'll sign: pk_S || client_id || transcript || salt
        transcript = chlo_transcript  # keep simple and consistent
        to_sign = pk_s + client_id + transcript + salt

        # ---- RSA sign pk_S binding ----
        rsa_priv = load_rsa_private_key(SERVER_KEY_PATH)
        signature = rsa_sign_pss_sha256(rsa_priv, to_sign)

        cert_pem = load_cert_pem(SERVER_CERT_PATH)

        shlo = build_shlo(pk_s, cert_pem, signature, salt)
        writer.write(frame_with_len(shlo))
        await writer.drain()

        # ---- Derive keys ----
        z = ecdhe_shared_secret(sk_s, pk_c)
        key_c2s, key_s2c = derive_session_keys(z, salt)

        # ---- Register session ----
        async with sessions_lock:
            # se já existir, substitui (reconexão)
            sessions[client_id] = Session(
                client_id=client_id,
                writer=writer,
                key_c2s=key_c2s,
                key_s2c=key_s2c,
                seq_recv=-1,
                seq_send=0,
                nonce_send=NonceStrategy.new(),
            )

        print(f"[+] Conectado: {peer} client_id={hex_id(client_id)}")

        # ---- Application loop ----
        while True:
            frame = await read_frame(reader)  # frame já é "app frame" (sem tipo)
            nonce, sender_id, recipient_id, seq_no, ct_tag, aad = parse_app_frame(frame)

            # Verifica sessão e anti-replay
            async with sessions_lock:
                sess = sessions.get(sender_id)
            if not sess:
                print(f"[!] Sessão não encontrada para sender={hex_id(sender_id)}")
                continue

            if seq_no <= sess.seq_recv:
                print(f"[!] Replay detectado sender={hex_id(sender_id)} seq={seq_no} <= {sess.seq_recv}")
                continue

            try:
                plaintext = aead_decrypt(sess.key_c2s, nonce, ct_tag, aad)
            except Exception:
                print(f"[!] Tag inválida / falha de autenticação sender={hex_id(sender_id)}")
                continue

            sess.seq_recv = seq_no

            # Roteia para destinatário
            async with sessions_lock:
                dest = sessions.get(recipient_id)

            if not dest:
                # opcional: avisar remetente
                print(f"[!] Destinatário offline: {hex_id(recipient_id)}")
                continue

            # Re-cifra para o destinatário (server->dest usa key_s2c do destinatário)
            out_seq = dest.seq_send
            out_nonce = dest.nonce_send.make(out_seq)
            out_aad = sender_id + recipient_id + out_seq.to_bytes(8, "big")

            out_ct_tag = aead_encrypt(dest.key_s2c, out_nonce, plaintext, out_aad)
            out_frame = build_app_frame(out_nonce, sender_id, recipient_id, out_seq, out_ct_tag)

            dest.writer.write(frame_with_len(out_frame))
            await dest.writer.drain()

            dest.seq_send += 1

    except asyncio.IncompleteReadError:
        print(f"[-] Cliente desconectou: {peer}")
    except Exception as e:
        print(f"[!] Erro com cliente {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        if client_id:
            async with sessions_lock:
                if sessions.get(client_id) and sessions[client_id].writer is writer:
                    sessions.pop(client_id, None)
            print(f"[-] Sessão removida client_id={hex_id(client_id)}")

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = server.sockets[0].getsockname()
    print(f"Servidor rodando em {addr}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
