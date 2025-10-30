# CipherCast

CipherCast is a lightweight peer-to-peer (P2P) CLI tool for secure communication.
It uses Elliptic Curve Cryptography (secp256k1) and symmetric encryption (AES-256) to enable end-to-end encryption between a sender and a receiver — without relying on a centralized server.

---

## Features
- Generate cryptographic keypairs (secp256k1).
- Send encrypted messages/files to a peer.
- Receive and decrypt messages/files securely.
- Pure Node.js (no external dependencies, minimal setup).

---

## Installation
```bash
git clone https://github.com/nifemibosun/ciphercast.git
cd ciphercast
npm run build
```
Now you can run ciphercast from anywhere.

---

## Usage
### Generate a keypair
```bash
ciphercast keygen
```
This will output a private key and a public key.
- Keep your private key safe (never share it).
- Share your public key with peers so they can send messages to you.

---

### Send a message/file
```bash
ciphercast send <senderPrivkeyHex> <senderPubkeyHex> <receiverPubkeyHex> <filePath> <host-ip> <host-port>
```
- file: Path to the file/message you want to send.
- recipient-public-key: The peer’s public key (for encryption).
- peer-address: Network address of the receiver (for P2P).

---

CipherCast will:
- Derive a shared secret using ECDH.
- Encrypt the file using AES-256.
- Send it to the peer.

---

### Receive a message/file
```bash
ciphercast recv <myPrivkeyHex> <outputDir> <host-port>
```
CipherCast will:
- Wait for incoming encrypted data.
- Decrypt it using your private key.
- Save the result to <output-file>.

---

## Disclaimer
Do not use in production without a proper security audit.

### Note:
CipherCast works best with IPv6.

---

## License
MIT License © 2025 Nifemi Bosun