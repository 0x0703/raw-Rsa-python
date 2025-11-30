# 🔐 RSA Encryption Tool

A Python implementation of the RSA cryptographic algorithm with a modern GUI interface.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- **Key Generation** — 512, 1024, or 2048-bit RSA keys using Miller-Rabin primality test
- **Encryption/Decryption** — Block cipher with Base64 output, full Unicode support
- **Standard Key Formats** — PEM (X.509, PKCS#8) compatible with OpenSSL
- **Modern GUI** — Dark theme interface built with tkinter
- **Cross-platform** — Works on Windows, macOS, and Linux

## 📸 Screenshots

<details>
<summary>Key Generation</summary>

Generate RSA key pairs in PEM or HEX format with selectable key sizes.
</details>

<details>
<summary>Encryption</summary>

Encrypt messages using public key, output in Base64 format.
</details>

<details>
<summary>Decryption</summary>

Decrypt messages using private key with automatic format detection.
</details>

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- tkinter (included with Python on most systems)

### Clone and Install

```bash
git clone https://github.com/yourusername/rsa-encryption.git
cd rsa-encryption
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

## 📖 Usage

### GUI Application

1. **Generate Keys** — Click "Generate Keys" on the Keys tab
2. **Encrypt** — Paste your message, go to Encrypt tab, click "Encrypt"
3. **Decrypt** — Paste encrypted text, go to Decrypt tab, click "Decrypt"

### As a Library

```python
from rsa_core import generate_keypair, encrypt_message, decrypt_message

# Generate 2048-bit keys
public_key, private_key = generate_keypair(2048)

# Encrypt
message = "Hello, World!"
encrypted = encrypt_message(message, public_key)
print(f"Encrypted: {encrypted}")

# Decrypt
decrypted = decrypt_message(encrypted, private_key)
print(f"Decrypted: {decrypted}")
```

### PEM Format Keys

```python
from rsa_core import generate_keypair, keys_to_pem, pem_to_keys

# Generate and export to PEM
public_key, private_key = generate_keypair(2048)
public_pem, private_pem = keys_to_pem(public_key, private_key)

# Save to files
with open("public_key.pem", "w") as f:
    f.write(public_pem)

with open("private_key.pem", "w") as f:
    f.write(private_pem)
```

## 📁 Project Structure

```
RSA/
├── rsa_core.py      # RSA cryptography core (algorithms, math)
├── main.py          # GUI application (tkinter)
├── requirements.txt # Dependencies
├── README.md        # This file
└── REPORT.html      # Technical documentation
```

## 🔧 Technical Details

### Algorithms

| Component | Implementation |
|-----------|----------------|
| Primality Test | Miller-Rabin (10 rounds, error ≤ 10⁻⁶) |
| Key Generation | Two random primes p, q; n = p×q |
| Public Exponent | e = 65537 (Fermat prime) |
| Private Exponent | Extended Euclidean Algorithm |
| Encryption | c = m^e mod n (block cipher) |
| Output Format | Base64 encoded |

### Key Formats

**Public Key — X.509 (SubjectPublicKeyInfo)**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----
```

**Private Key — PKCS#8**
```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----
```

### OpenSSL Compatibility

Keys are compatible with OpenSSL:

```bash
# Verify private key
openssl rsa -in private_key.pem -check

# Extract public key
openssl rsa -in private_key.pem -pubout -out public.pem

# View key details
openssl rsa -in private_key.pem -text -noout
```

## ⚠️ Important Notes

This is an **educational implementation** of RSA (Textbook RSA) without padding.

| Aspect | This Implementation | Production Standard |
|--------|---------------------|---------------------|
| Padding | None | OAEP (RFC 8017) |
| Key Format | ✅ PEM (X.509, PKCS#8) | ✅ PEM |
| Ciphertext | Base64 blocks | ASN.1 DER |

**For production use**, consider using the `cryptography` library with OAEP padding:

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

## 🛠️ Dependencies

- `cryptography` — For PEM key format support (optional)
- `tkinter` — GUI (included with Python)

## 📄 License

MIT License — feel free to use for educational purposes.
