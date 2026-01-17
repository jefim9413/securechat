# SecureChat — Mensageria Segura Multi-Cliente

## 1. Descrição Geral

O SecureChat é uma aplicação de mensageria segura multi-cliente baseada em TCP puro, onde múltiplos clientes se conectam a um servidor central para trocar mensagens de forma protegida.

O protocolo de segurança foi implementado manualmente, sem uso de TLS, conforme solicitado no trabalho, garantindo confidencialidade, integridade, autenticidade do servidor e sigilo perfeito (forward secrecy).

---

## 2. Objetivos de Segurança

O sistema foi projetado para proteger contra os seguintes ataques:

* Escuta passiva (sniffing)
* Modificação de mensagens
* Ataques de replay
* Ataques Man-in-the-Middle (MITM)
* Comprometimento futuro da chave RSA do servidor

---

## 3. Mecanismos Criptográficos Utilizados

### 3.1 Troca de Chaves e Autenticação

* **ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)**

  * Curva P-256
  * Responsável por garantir o sigilo perfeito

* **RSA 2048 bits com certificado autoassinado**

  * O servidor assina sua chave ECDHE efêmera
  * O cliente valida usando certificate pinning
  * Garante a autenticidade do servidor

* **HKDF (HMAC-SHA256)**

  * Deriva chaves simétricas seguras
  * Gera chaves distintas para cada direção da comunicação

### 3.2 Proteção das Mensagens

* **AES-128-GCM (AEAD)**

  * Confidencialidade
  * Integridade
  * Autenticidade

* **AAD (Associated Authenticated Data)**

  * sender_id
  * recipient_id
  * seq_no

* **Anti-replay**

  * seq_no monotônico por sessão

---

## 4. Estrutura da Mensagem

```
nonce (12B) | sender_id (16B) | recipient_id (16B) | seq_no (8B) | ciphertext + tag
```

* O nonce é único por mensagem e por direção
* O seq_no impede ataques de replay
* O ciphertext e a tag são gerados pelo AES-GCM

---

## 5. Estrutura de Sessão no Servidor

```python
sessions = {
    client_id: {
        "writer": StreamWriter,
        "key_c2s": AES key,
        "key_s2c": AES key,
        "seq_recv": int,
        "seq_send": int,
        "nonce_prefix": bytes
    }
}
```

---

## 6. Requisitos

* Python 3.10 ou superior
* Biblioteca cryptography

Instalação da dependência:

```
pip install cryptography
```

---

## 7. Geração do Certificado do Servidor

O servidor utiliza um certificado RSA autoassinado.

```
python generate_cert.py
```

Arquivos gerados:

* server_key.pem (uso exclusivo do servidor)
* server_cert.pem (servidor e clientes)

---

## 8. Como Executar

### 8.1 Iniciar o servidor

```
python server.py
```

### 8.2 Iniciar os clientes

```
python client.py
```

Cada cliente exibirá um client_id em hexadecimal.

### 8.3 Troca de IDs

Cada cliente deve informar manualmente o client_id do outro cliente como destinatário.

### 8.4 Envio de Mensagens

Digite mensagens no terminal.
Para sair da aplicação:

```
/quit
```

---

## 9. Demonstração de Segurança

Durante a execução do sistema, é possível observar que:

* Apenas o destinatário correto consegue decifrar a mensagem
* Mensagens alteradas falham na verificação da tag GCM
* Mensagens repetidas são rejeitadas pelo mecanismo anti-replay
* O servidor valida a integridade antes de reencaminhar mensagens

---

## 10. Observações Finais

Este projeto implementa manualmente conceitos fundamentais de protocolos seguros modernos, inspirados no TLS 1.3, com finalidade exclusivamente acadêmica.
