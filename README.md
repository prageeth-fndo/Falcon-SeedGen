# 🪶 Falcon SeedGen
### Deterministic Falcon PQC keypair generation from a custom seed  
---

`Falcon SeedGen` is a lightweight **C + Python toolkit** that enables **deterministic keypair generation** for the Falcon post-quantum signature schemes (`falcon-512`, `falcon-padded-512`, `falcon-1024`, `falcon-padded-1024`) using a **user-supplied seed**.

It is ideal for:

- **Research & protocol testing**  
- **Deterministic PQC wallets**  
- **Reproducible cryptographic experiments**  
- **Benchmarking & academic work**  

The implementation relies on official algorithm code from the **PQClean** project.

⚠️ **Not intended for production cryptographic deployments without a full security review.**

---

## ✨ Features

- 🔐 Deterministic Falcon keypair generation from any seed  
- 📦 Supports all Falcon variants:
  - `falcon-512`
  - `falcon-padded-512`
  - `falcon-1024`
  - `falcon-padded-1024`
- ⚙️ Pure C core for maximum performance  
- 🐍 Python wrapper (ctypes) for easy integration  
- 🔁 SHAKE256-based DRBG ensures deterministic randomness  
- 🧼 Clean and minimal codebase  
- ❌ No external crypto libraries required  

---

## 📁 Directory Structure

```
falcon-seedgen/
│
├── c/
│   ├── Makefile
│   ├── falcon-seedgen.c           # DRBG + deterministic keygen implementation
│   └── libfalconseedgen.so        # (created by make, NOT included in repo)
│
├── PQClean/
│   ├── falcon/
│   │   ├── falcon-512/
│   │   ├── falcon-padded-512/
│   │   ├── falcon-1024/
│   │   └── falcon-padded-1024/
│   └── common/
│       ├── fips202.c
│       └── fips202.h
│
├── falcon_seedgen.py              # Python ctypes wrapper
└── README.md
```

---

## 🛠️ Build Instructions

### **1. Clone the repository**
```bash
git clone https://github.com/prageeth-fndo/Falcon-SeedGen.git
cd Falcon-SeedGen/c
```

### **2. Build the shared library**
```bash
make
```

After compiling, you should see:

```
libfalconseedgen.so
```

This library is used by the Python wrapper.

---

## 🐍 Python Usage

```python
from falcon_seedgen import (
    falcon512_from_seed,
    falcon512_padded_from_seed,
    falcon1024_from_seed,
    falcon1024_padded_from_seed,
)

seed = b'\x01' * 32  # custom seed (any length ≤ 64 bytes)

sk, pk = falcon512_from_seed(seed)

print("Secret key length:", len(sk))
print("Public key length:", len(pk))
```

### **Expected output**
```
Secret key length: 1281
Public key length: 897
```

---

## ⚙️ How It Works

Falcon normally requires randomness during key generation.  
This project replaces the randomness source with a **deterministic SHAKE256-based DRBG**:

```
DRBG(seed) → pseudo-random stream → Falcon keygen
```

Benefits:

- ✔ Reproducible keypairs  
- ✔ Deterministic behavior for testing  
- ✔ Suitable for HD-wallet research  
- ✔ Ideal for protocol simulations  

---

## 🛡 Security Notes

- ❗ This is a **demo**, not production-hardened  
- 🔒 Deterministic keys reduce entropy protections  
- 🗝 Seed handling is the user’s responsibility  
- 🚫 Do NOT use in production environment without full threat modeling  

---

## 📜 License

PQClean source code is included under its corresponding permissive licenses.

---

## 🤝 Acknowledgements

- PQClean team for reference Falcon implementations  
- Falcon authors for the cryptographic design  
- NIST PQC project  

---

## ⭐ Support & Contributions

Pull requests, performance improvements, seed-handling utilities, and Python enhancements are welcome.  
If you build something cool on top of this, share it with the community!
