# 🔐 Intermediate Cryptography Tool

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-green)
![Education](https://img.shields.io/badge/Purpose-Educational%20Only-orange)
![Security](https://img.shields.io/badge/Security-Research%20Only-red)

**Created by Soumit Santra — Educational Cryptography & Cryptanalysis Tool**  
© 2025 [Your Name]. All rights reserved.

---

## ⚠️ CRITICAL LEGAL & ETHICAL NOTICE

> **THIS TOOL IS STRICTLY FOR EDUCATIONAL AND AUTHORIZED RESEARCH ONLY!**
>
> - **DO NOT USE** for illegal activities, unauthorized access, or malicious purposes
> - **OBTAIN EXPLICIT PERMISSION** before testing on any systems you don't own
> - **CRYPTANALYSIS TOOLS** are for learning purposes and authorized security research only
> - **THE AUTHOR IS NOT RESPONSIBLE** for misuse, damages, or illegal activities
> - **SOME TECHNIQUES** may be illegal in your jurisdiction - check local laws

**Ethical Use Only:**
- Educational learning and understanding cryptographic concepts
- Authorized security research and penetration testing
- Academic coursework and research projects
- Personal skill development in controlled environments
- **Never use against systems without explicit written permission**

---

## 📚 Educational Purpose

This tool is designed to help students, researchers, and security professionals understand:
- Classical cipher mechanisms and their vulnerabilities
- Modern cryptographic implementations
- Cryptanalysis techniques and their limitations
- Security analysis methodologies
- The evolution from classical to modern cryptography

---

## ✨ Features

### 🏛️ Classical Ciphers
- **Caesar Cipher** - Enhanced with extended character set
- **Vigenère Cipher** - Polyalphabetic substitution
- **Playfair Cipher** - Digraph substitution cipher
- **Rail Fence Cipher** - Zigzag transposition
- **Atbash Cipher** - Alphabet reversal
- **ROT13** - Simple letter rotation

### 🔤 Encoding/Decoding
- **Base64** encoding and decoding
- **Hexadecimal** conversion
- **Binary** representation
- **Morse Code** translation

### 🔐 Modern Cryptography
- **Fernet** symmetric encryption (AES-based)
- **RSA** asymmetric encryption
- **Elliptic Curve Cryptography (ECC)**
- **Digital Signatures** (RSA/ECDSA)
- **HMAC** (Message Authentication Code)
- **Password-based Encryption** (PBKDF2)

### 🔍 Analysis Tools
- **Frequency Analysis** with visualization
- **Language Detection** using statistical methods
- **Chi-squared Analysis** for cipher identification
- **Entropy Analysis** for randomness testing
- **N-gram Analysis** for pattern recognition
- **Index of Coincidence** calculations

### 🛠️ Cryptanalysis (Educational)
- **Caesar Brute Force** with language scoring
- **Vigenère Key Length** estimation
- **Kasiski Examination** for repeated sequences
- **Statistical Cipher Identification**
- **Markov Chain Analysis**

### 🕵️ Steganography
- **Image Steganography** (LSB method)
- **Text Steganography** (whitespace encoding)
- Audio and file format steganography (scaffolds)

### 🛡️ Advanced Features
- **Hash Functions** (MD5, SHA family)
- **Key Generation** utilities
- **Secure Key Storage** in memory
- **Quantum-resistant** algorithm scaffolds
- **Timing Attack** simulation

---

## 🛠️ Requirements

- Python **3.7+**
- The script automatically installs required packages:
  - `pycryptodome`
  - `cryptography`
  - `requests`
  - `colorama`
  - `tqdm`
  - `Pillow` (PIL)

---

## 💻 Installation

### Quick Start

1. **Download the script**
2. **Run with Python:**
   ```bash
   python crypto_tool.py
   ```
3. **Dependencies install automatically** on first run

### Manual Installation

```bash
# Clone or download the repository
git clone [repository-url]
cd cryptography-tool

# Install dependencies (optional - auto-installs on run)
pip install pycryptodome cryptography requests colorama tqdm Pillow

# Run the tool
python crypto_tool.py
```

---

## 🚦 Usage

### Interactive Menu System

Run the script and choose from 44+ different cryptographic operations:

```
CLASSIC CIPHERS:
1. Caesar Cipher (Enhanced)
2. Vigenère Cipher
3. Playfair Cipher
[...]

MODERN ENCRYPTION:
19. Fernet (Encrypt/Decrypt)
20. RSA (Encrypt/Decrypt)
[...]

ANALYSIS TOOLS:
12. Frequency Analysis
13. Language Detection
[...]
```

### Example Usage

**Encrypt with Caesar Cipher:**
```
Choose option: 1
Encrypt or Decrypt? (e/d): e
Enter text: Hello World
Enter shift value: 3
Encrypted: Khoor Zruog
```

**Frequency Analysis:**
```
Choose option: 12
Enter text for frequency analysis: HELLO WORLD
[Displays frequency histogram]
```

**RSA Key Generation:**
```
Choose option: 21
Enter key size (default 2048): 2048
[Generates and displays RSA key pair]
```

---

## 📊 Educational Examples

### Classical Cipher Breaking

Learn how classical ciphers can be broken:
- Use frequency analysis to identify substitution patterns
- Apply statistical methods to determine cipher types
- Understand the importance of key length in security

### Modern Cryptography

Explore secure implementations:
- Generate proper cryptographic keys
- Understand the difference between symmetric and asymmetric encryption
- Learn about digital signatures and authentication

### Cryptanalysis Techniques

**Educational cryptanalysis methods:**
- Kasiski examination for Vigenère ciphers
- Statistical analysis for cipher identification
- Entropy testing for randomness assessment

---

## 🎓 Learning Objectives

This tool helps users understand:

1. **Historical Cryptography** - Why classical ciphers are vulnerable
2. **Modern Security** - How current systems protect data
3. **Cryptanalysis** - Methods for analyzing unknown ciphers
4. **Implementation** - Proper use of cryptographic libraries
5. **Security Principles** - Best practices in cryptographic design

---

## ⚖️ Legal Considerations

### Allowed Uses
- ✅ Educational learning and coursework
- ✅ Authorized security research
- ✅ Academic research projects
- ✅ Personal skill development
- ✅ Penetration testing with written permission

### Prohibited Uses
- ❌ Unauthorized system access
- ❌ Breaking encryption without permission
- ❌ Illegal surveillance or espionage
- ❌ Academic dishonesty or cheating
- ❌ Any malicious or harmful activities

---

## 🔒 Security Notes

- **Keys are stored in memory only** during execution
- **No persistent key storage** by default
- **Educational implementations** may not be production-ready
- **Some algorithms are deprecated** (MD5, etc.) - included for learning only
- **Use production libraries** for real applications

---

## 🚨 Responsible Disclosure

If you discover vulnerabilities in the educational implementations:
1. Do not exploit them maliciously
2. Document the issue responsibly  
3. Use findings for educational purposes only
4. Consider contributing improvements

---

## 🤝 Contributing

Contributions welcome for:
- Educational improvements
- Additional cipher implementations
- Better documentation
- Security enhancements
- Bug fixes

Please ensure all contributions maintain the educational focus and ethical guidelines.

---

## 📚 Further Reading

**Recommended Resources:**
- "Applied Cryptography" by Bruce Schneier
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno
- "The Code Book" by Simon Singh
- NIST Cryptographic Standards
- Academic cryptography courses

---

## ⚠️ Final Warning

**This tool contains powerful cryptanalysis capabilities. Use them responsibly:**

- Never attempt to break encryption without explicit authorization
- Respect privacy and legal boundaries
- Use knowledge gained for constructive purposes
- Remember that unauthorized access is illegal in most jurisdictions
- When in doubt, don't use the tool

**The power to understand cryptography comes with the responsibility to use that knowledge ethically.**

---

## 📄 License

This educational tool is provided for learning purposes. Users are responsible for ensuring their use complies with applicable laws and ethical standards.

---

*"Knowledge is power, but with power comes responsibility. Use cryptographic knowledge to protect, not to harm."*
