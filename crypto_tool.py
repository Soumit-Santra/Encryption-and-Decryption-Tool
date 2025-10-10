"""
Cryptography-Tool
========================================================================

Copyright (c) 2025 [Soumit Santra]
All rights reserved.

===================================================================
Author: [Soumit Santra]
Version: 1.0
Created: 2025
Last Modified: 2025
"""

import sys
import subprocess
import pkg_resources 
import importlib.metadata

# Check, install, and update required packages
def check_and_install_packages():
    required_packages = {
        'pycryptodome': 'Crypto',  # For AES, RSA, etc.
        'cryptography': 'cryptography',  # For modern crypto functions.
        'requests': 'requests',  # For version checking.
        'colorama': 'colorama',  # For colored output.
        'tqdm': 'tqdm'  # For progress bars.
    }
    
    def install_package(package):
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"Successfully installed {package}")
        except subprocess.CalledProcessError:
            print(f"Failed to install {package}")
            return False
        return True

    def update_package(package):
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", package])
            print(f"Successfully updated {package}")
        except subprocess.CalledProcessError:
            print(f"Failed to update {package}")
            return False
        return True

    def get_latest_version(package):
        try:
            import requests
            response = requests.get(f"https://pypi.org/pypi/{package}/json")
            return response.json()['info']['version']
        except:
            return None

    print("Checking required packages...")
    for package, import_name in required_packages.items():
        try:
            importlib.import_module(import_name)
            current_version = pkg_resources.get_distribution(package).version
            latest_version = get_latest_version(package)
            
            if latest_version and current_version < latest_version:
                print(f"Updating {package} from {current_version} to {latest_version}")
                update_package(package)
            else:
                print(f"✓ {package} is up to date (version {current_version})")
                
        except ImportError:
            print(f"Installing missing package: {package}")
            install_package(package)

# Run package check at startup
check_and_install_packages()

# Now import the required packages
import string
import random
import base64
import hashlib
import os
from collections import Counter
import math
import binascii
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
from colorama import init, Fore, Style
from tqdm import tqdm
import secrets
import hmac as py_hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, utils
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from PIL import Image
import io

# Initialize colorama
init()

class IntermediateCryptoTool:
    def __init__(self):
        # Character sets for various ciphers
        self.alphabet = string.ascii_lowercase
        self.extended_alphabet = string.ascii_letters + string.digits + string.punctuation
        self.fernet_key = None
        self.rsa_key = None
        self.secure_storage = {}
        self.ecc_private_key = None
        self.ecc_public_key = None

    #  CLASSIC CIPHERS 
    # Caesar cipher encryption with extended character set
    def caesar_encrypt(self, text, shift):
        result = ""
        for char in text:
            if char in self.extended_alphabet:
                old_pos = self.extended_alphabet.index(char)
                new_pos = (old_pos + shift) % len(self.extended_alphabet)
                result += self.extended_alphabet[new_pos]
            else:
                result += char
        return result
    
    # Caesar cipher decryption (simply negative shift)
    def caesar_decrypt(self, text, shift):
        return self.caesar_encrypt(text, -shift)
    
    # Vigenère cipher encryption (classic polyalphabetic cipher)
    def vigenere_encrypt(self, text, key):
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.upper()
                
                key_char = key[key_index % len(key)]
                
                char_pos = ord(char) - ord('A')
                key_pos = ord(key_char) - ord('A')
                encrypted_pos = (char_pos + key_pos) % 26
                encrypted_char = chr(encrypted_pos + ord('A'))
                
                if not is_upper:
                    encrypted_char = encrypted_char.lower()
                
                result += encrypted_char
                key_index += 1
            else:
                result += char
        
        return result
    
    # Vigenère cipher decryption
    def vigenere_decrypt(self, text, key):
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.upper()
                
                key_char = key[key_index % len(key)]
                
                char_pos = ord(char) - ord('A')
                key_pos = ord(key_char) - ord('A')
                decrypted_pos = (char_pos - key_pos) % 26
                decrypted_char = chr(decrypted_pos + ord('A'))
                
                if not is_upper:
                    decrypted_char = decrypted_char.lower()
                
                result += decrypted_char
                key_index += 1
            else:
                result += char
        
        return result
    
    # Playfair cipher encryption (digraph substitution)
    def playfair_encrypt(self, text, key):
        matrix = self.create_playfair_matrix(key)
        text = self.prepare_playfair_text(text)
        
        result = ""
        for i in range(0, len(text), 2):
            if i + 1 < len(text):
                result += self.playfair_encrypt_pair(text[i], text[i+1], matrix)
            else:
                result += self.playfair_encrypt_pair(text[i], 'X', matrix)
        
        return result
    
    # Playfair cipher decryption
    def playfair_decrypt(self, text, key):
        matrix = self.create_playfair_matrix(key)
        
        result = ""
        for i in range(0, len(text), 2):
            if i + 1 < len(text):
                result += self.playfair_decrypt_pair(text[i], text[i+1], matrix)
        
        return result
    
    # Create 5x5 Playfair matrix from key
    def create_playfair_matrix(self, key):
        key = key.upper().replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        
        seen = set()
        unique_key = ""
        for char in key:
            if char not in seen and char in alphabet:
                unique_key += char
                seen.add(char)
        
        for char in alphabet:
            if char not in seen:
                unique_key += char
        
        matrix = []
        for i in range(5):
            matrix.append(unique_key[i*5:(i+1)*5])
        
        return matrix
    
    # Prepare text for Playfair cipher (remove non-alpha, handle double letters)
    def prepare_playfair_text(self, text):
        text = text.upper().replace('J', 'I')
        text = ''.join(char for char in text if char.isalpha())
        
        prepared = ""
        i = 0
        while i < len(text):
            prepared += text[i]
            if i + 1 < len(text) and text[i] == text[i + 1]:
                prepared += 'X'
            i += 1
        
        if len(prepared) % 2 == 1:
            prepared += 'X'
        
        return prepared
    
    # Find row and column of character in Playfair matrix
    def find_position(self, char, matrix):
        for i, row in enumerate(matrix):
            if char in row:
                return i, row.index(char)
        return None, None
    
    # Encrypt a pair of characters using Playfair rules
    def playfair_encrypt_pair(self, char1, char2, matrix):
        row1, col1 = self.find_position(char1, matrix)
        row2, col2 = self.find_position(char2, matrix)
        
        if row1 == row2:
            return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            return matrix[row1][col2] + matrix[row2][col1]
    
    # Decrypt a pair of characters using Playfair rules
    def playfair_decrypt_pair(self, char1, char2, matrix):
        row1, col1 = self.find_position(char1, matrix)
        row2, col2 = self.find_position(char2, matrix)
        
        if row1 == row2:
            return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            return matrix[row1][col2] + matrix[row2][col1]
    
    # Rail Fence cipher encryption (zigzag transposition)
    def rail_fence_encrypt(self, text, rails):
        if rails == 1:
            return text
        
        fence = [['' for _ in range(len(text))] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for i, char in enumerate(text):
            fence[rail][i] = char
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        result = ""
        for row in fence:
            result += ''.join(row)
        
        return result
    
    # Rail Fence cipher decryption
    def rail_fence_decrypt(self, text, rails):
        if rails == 1:
            return text
        
        fence = [['' for _ in range(len(text))] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for i in range(len(text)):
            fence[rail][i] = '*'
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        index = 0
        for i in range(rails):
            for j in range(len(text)):
                if fence[i][j] == '*':
                    fence[i][j] = text[index]
                    index += 1
        
        result = ""
        rail = 0
        direction = 1
        
        for i in range(len(text)):
            result += fence[rail][i]
            rail += direction
            
            if rail == rails - 1 or rail == 0:
                direction *= -1
        
        return result
    
    # Atbash cipher (alphabet reversal)
    def atbash_encrypt(self, text):
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result += chr(ord('Z') - (ord(char) - ord('A')))
                else:
                    result += chr(ord('z') - (ord(char) - ord('a')))
            else:
                result += char
        return result
    
    # Atbash cipher decryption (same as encryption)
    def atbash_decrypt(self, text):
        return self.atbash_encrypt(text)
    
    # ROT13 cipher encryption/decryption (simple letter rotation)
    def rot13_encrypt(self, text):
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            else:
                result += char
        return result
    
    # ROT13 cipher decryption (same as encryption)
    def rot13_decrypt(self, text):
        return self.rot13_encrypt(text)
    
    #  ENCODING/DECODING 

    # Base64 encoding (text to base64 string)
    def base64_encode(self, text):
        return base64.b64encode(text.encode()).decode()
    
    # Base64 decoding (base64 string to text)
    def base64_decode(self, text):
        try:
            return base64.b64decode(text).decode()
        except Exception as e:
            return f"Error decoding: {e}"
    
    # Hexadecimal encoding (text to hex string)
    def hex_encode(self, text):
        return text.encode().hex()
    
    # Hexadecimal decoding (hex string to text)
    def hex_decode(self, text):
        try:
            return bytes.fromhex(text).decode()
        except Exception as e:
            return f"Error decoding: {e}"
    
    # Binary encoding (text to binary string)
    def binary_encode(self, text):
        return ' '.join(format(ord(char), '08b') for char in text)
    
    # Binary decoding (binary string to text)
    def binary_decode(self, text):
        try:
            binary_values = text.split()
            return ''.join(chr(int(binary, 2)) for binary in binary_values)
        except Exception as e:
            return f"Error decoding: {e}"
    
    # Morse code encoding (text to Morse)
    def morse_encode(self, text):
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/', '.': '.-.-.-', ',': '--..--', '?': '..--..',
            '!': '-.-.--', ':': '---...', ';': '-.-.-.', "'": '.----.', '-': '-....-',
            '_': '..--.-', '"': '.-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
            '@': '.--.-.', '=': '-...-', '+': '.-.-.', '$': '...-..-'
        }
        
        result = []
        for char in text.upper():
            if char in morse_dict:
                result.append(morse_dict[char])
            else:
                result.append(char)
        
        return ' '.join(result)
    
    # Morse code decoding (Morse to text)
    def morse_decode(self, text):
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
            '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
            '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '/': ' ', '.-.-.-': '.', '--..--': ',', '..--..': '?',
            '-.-.--': '!', '---...': ':', '-.-.-.': ';', '.----.': "'", '-....-': '-',
            '..--.-': '_', '.-..-.': '"', '-.--.': '(', '-.--.-': ')', '.-...': '&',
            '.--.-.': '@', '-...-': '=', '.-.-.': '+', '...-..-': '$'
        }
        
        result = []
        for code in text.split():
            if code in morse_dict:
                result.append(morse_dict[code])
            else:
                result.append(code)
        
        return ''.join(result)
    
    #  HASH FUNCTIONS 

    # Hash text using specified algorithm (MD5, SHA1, SHA256, etc.)
    def hash_text(self, text, algorithm='sha256'):
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in algorithms:
            return "Unsupported algorithm"
        
        return algorithms[algorithm](text.encode()).hexdigest()
    
    #  ANALYSIS TOOLS 

    # Frequency analysis: count letter frequencies and show histogram
    def frequency_analysis(self, text):
        text = ''.join(char.upper() for char in text if char.isalpha())
        
        if not text:
            return "No alphabetic characters found"
        
        counter = Counter(text)
        total = len(text)
        
        print("Frequency Analysis:")
        print("-" * 35)
        print("Letter | Count | Frequency | Graph")
        print("-" * 35)
        
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            count = counter.get(letter, 0)
            frequency = (count / total) * 100 if total > 0 else 0
            bar = '█' * int(frequency / 2)
            print(f"   {letter}   |  {count:3d}  |   {frequency:5.1f}%  | {bar}")
        
        return counter
    
    # Simple language detection based on English letter frequency
    def detect_language(self, text):
        english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        
        text = ''.join(char.upper() for char in text if char.isalpha())
        if not text:
            return "No alphabetic characters found"
        
        counter = Counter(text)
        total = len(text)
        
        chi_squared = 0
        for letter in string.ascii_uppercase:
            observed = counter.get(letter, 0)
            expected = (english_freq.get(letter, 0) / 100) * total
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected
        
        if chi_squared < 50:
            return "Likely English text"
        elif chi_squared < 100:
            return "Possibly English text"
        else:
            return "Unlikely to be English text"
    
    #  BRUTE FORCE TOOLS 
    # Brute force Caesar cipher and analyze each shift for English likelihood
    def brute_force_caesar(self, text):
        print("Caesar Cipher Brute Force Analysis:")
        print("-" * 60)
        
        best_candidates = []
        
        for shift in range(26):
            decrypted = self.caesar_decrypt(text, shift)
            language_score = self.detect_language(decrypted)
            
            print(f"Shift {shift:2d}: {decrypted[:50]}...")
            print(f"         Language: {language_score}")
            print()
            
            if "Likely English" in language_score or "Possibly English" in language_score:
                best_candidates.append((shift, decrypted, language_score))
        
        if best_candidates:
            print("\nBest Candidates:")
            print("-" * 40)
            for shift, text, score in best_candidates:
                print(f"Shift {shift:2d} ({score}): {text}")
        else:
            print("No likely English text found in any shift.")
        
        return best_candidates
    
    # Estimate Vigenère key length using Index of Coincidence
    def brute_force_vigenere_key_length(self, text, max_key_length=20):
        text = ''.join(char.upper() for char in text if char.isalpha())
        
        print("Vigenère Key Length Analysis (Index of Coincidence):")
        print("-" * 55)
        print("Key Length | Index of Coincidence | Likelihood")
        print("-" * 55)
        
        likely_lengths = []
        
        for key_length in range(1, min(max_key_length + 1, len(text) // 2)):
            ic_sum = 0
            
            for i in range(key_length):
                subsequence = text[i::key_length]
                if len(subsequence) > 1:
                    counter = Counter(subsequence)
                    n = len(subsequence)
                    ic = sum(count * (count - 1) for count in counter.values()) / (n * (n - 1))
                    ic_sum += ic
            
            avg_ic = ic_sum / key_length if key_length > 0 else 0
            
            likelihood = "High" if avg_ic > 0.06 else "Medium" if avg_ic > 0.045 else "Low"
            if avg_ic > 0.06:
                likely_lengths.append(key_length)
            
            print(f"    {key_length:2d}     |       {avg_ic:.4f}       |    {likelihood}")
        
        if likely_lengths:
            print(f"\nMost likely key lengths: {likely_lengths}")
        else:
            print("\nNo highly likely key lengths found.")
        
        return likely_lengths
    
    #  MODERN ENCRYPTION 
    # Generate a new Fernet key for symmetric encryption
    def generate_fernet_key(self):
        self.fernet_key = Fernet.generate_key()
        return self.fernet_key

    # Encrypt text using Fernet (symmetric encryption)
    def fernet_encrypt(self, text):
        if not self.fernet_key:
            self.generate_fernet_key()
        f = Fernet(self.fernet_key)
        return f.encrypt(text.encode()).decode()

    # Decrypt text using Fernet (symmetric encryption)
    def fernet_decrypt(self, text):
        if not self.fernet_key:
            raise ValueError("No Fernet key available. Generate or load a key first.")
        f = Fernet(self.fernet_key)
        return f.decrypt(text.encode()).decode()

    # Generate RSA key pair (asymmetric encryption)
    def generate_rsa_keypair(self, size=2048):
        self.rsa_key = RSA.generate(size)
        return {
            'private': self.rsa_key.export_key().decode(),
            'public': self.rsa_key.publickey().export_key().decode()
        }

    # Encrypt text using RSA (asymmetric encryption)
    def rsa_encrypt(self, text, public_key=None):
        if not public_key and not self.rsa_key:
            raise ValueError("No RSA key available")
        key = RSA.import_key(public_key) if public_key else self.rsa_key.publickey()
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(text.encode('utf-8')).hex()

    # Decrypt text using RSA (asymmetric encryption)
    def rsa_decrypt(self, text, private_key=None):
        if not private_key and not self.rsa_key:
            raise ValueError("No RSA private key available")
        key = RSA.import_key(private_key) if private_key else self.rsa_key
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(bytes.fromhex(text)).decode('utf-8')

    #  ADVANCED CRYPTANALYSIS 
    # Kasiski examination for Vigenère cipher breaking (find repeated sequences and spacings)
    def kasiski_examination(self, ciphertext):
        ciphertext = ''.join([c for c in ciphertext.upper() if c.isalpha()])
        seq_spacings = {}
        for seq_len in range(3, 6):
            for i in range(len(ciphertext) - seq_len):
                seq = ciphertext[i:i+seq_len]
                for j in range(i+seq_len, len(ciphertext) - seq_len):
                    if ciphertext[j:j+seq_len] == seq:
                        if seq not in seq_spacings:
                            seq_spacings[seq] = []
                        seq_spacings[seq].append(j - i)
        factors = Counter()
        for spacings in seq_spacings.values():
            for space in spacings:
                for f in range(2, 21):
                    if space % f == 0:
                        factors[f] += 1
        print("Kasiski Examination Results:")
        print("Likely key lengths (factor counts):")
        for k, v in factors.most_common(10):
            print(f"  {k}: {v} times")
        return dict(factors)

    # Chi-squared analysis for monoalphabetic substitution cipher
    def chi_squared_substitution(self, ciphertext):
        english_freq = [
            8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
            0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
            2.758, 0.978, 2.360, 0.150, 1.974, 0.074
        ]
        text = ''.join([c.upper() for c in ciphertext if c.isalpha()])
        if not text:
            print("No alphabetic characters found.")
            return None
        observed = [text.count(chr(i+65)) for i in range(26)]
        total = sum(observed)
        chi2 = 0
        for i in range(26):
            expected = english_freq[i] * total / 100
            if expected > 0:
                chi2 += (observed[i] - expected) ** 2 / expected
        print(f"Chi-squared statistic: {chi2:.2f}")
        if chi2 < 150:
            print("Likely monoalphabetic substitution or English text.")
        else:
            print("Unlikely to be simple substitution/English.")
        return chi2

    # Linear cryptanalysis scaffold (block ciphers)
    def linear_cryptanalysis(self, ciphertext):
        print("Linear cryptanalysis not yet implemented (scaffold).")
        return None

    # Algebraic attack scaffold (block ciphers)
    def algebraic_attack(self, ciphertext):
        print("Algebraic attack not yet implemented (scaffold).")
        return None

    # Statistical tests for cipher identification (chi-squared and entropy)
    def statistical_cipher_id(self, ciphertext):
        # Use chi-squared and entropy as a simple test
        chi2 = self.chi_squared_substitution(ciphertext)
        ent = self.entropy_analysis(ciphertext)
        print(f"Statistical ID: Chi2={chi2:.2f}, Entropy={ent:.2f}")
        if chi2 is not None and ent is not None:
            if chi2 < 150 and ent < 4.5:
                print("Likely classical cipher or English text.")
            elif ent > 4.5:
                print("Likely modern cipher or compressed data.")
        return {"chi2": chi2, "entropy": ent}

    #  DIGITAL SIGNATURES 

    # Digital signature generation/verification (RSA/ECDSA)
    def digital_signature(self, message, algo='rsa'):
        if algo == 'rsa':
            if not self.rsa_key:
                self.generate_rsa_keypair()
            private_key = RSA.import_key(self.rsa_key.export_key())
            signer = PKCS1_OAEP.new(private_key)
            digest = hashlib.sha256(message.encode()).digest()
            signature = private_key.sign(digest, '')[0]
            print(f"Signature (int): {signature}")
            # Verification
            public_key = private_key.publickey()
            try:
                verified = public_key.verify(digest, (signature,))
                print("Signature verified:", verified)
            except Exception as e:
                print("Verification failed:", e)
            return signature
        elif algo == 'ecdsa':
            if not self.ecc_private_key:
                self.elliptic_curve_crypto('keygen')
            private_key = self.ecc_private_key
            signature = private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
            print(f"ECDSA signature: {binascii.hexlify(signature).decode()}")
            # Verification
            public_key = self.ecc_public_key
            try:
                public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
                print("Signature verified: True")
            except InvalidSignature:
                print("Signature verified: False")
            return signature
        else:
            print(f"Digital signature ({algo}) not supported.")
            return None

    #  HMAC (MAC) 
    # Message Authentication Code (HMAC) using SHA256/SHA512
    def hmac_mac(self, message, key, algo='sha256'):
        if algo not in ['sha256', 'sha512']:
            print("Unsupported HMAC algorithm.")
            return None
        digestmod = hashlib.sha256 if algo == 'sha256' else hashlib.sha512
        mac = py_hmac.new(key.encode(), message.encode(), digestmod).hexdigest()
        print(f"HMAC-{algo}: {mac}")
        return mac

    #  PASSWORD-BASED ENCRYPTION 
    # Password-based encryption using PBKDF2 (key derivation)
    def password_based_encryption(self, password, data, algo='pbkdf2'):
        if algo == 'pbkdf2':
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            f = Fernet(base64.urlsafe_b64encode(key))
            encrypted = f.encrypt(data.encode())
            print(f"Salt (hex): {salt.hex()}")
            print(f"Encrypted: {encrypted.decode()}")
            return {"salt": salt.hex(), "encrypted": encrypted.decode()}
        else:
            print(f"Password-based encryption ({algo}) not implemented.")
            return None

    #  ECC (Elliptic Curve Cryptography) 
    # ECC key generation, sign, and verify using cryptography library
    def elliptic_curve_crypto(self, operation='keygen', curve='secp256k1'):
        if operation == 'keygen':
            self.ecc_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
            self.ecc_public_key = self.ecc_private_key.public_key()
            priv_bytes = self.ecc_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
            pub_bytes = self.ecc_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            print("ECC Private Key:\n", priv_bytes.decode())
            print("ECC Public Key:\n", pub_bytes.decode())
            return {"private": priv_bytes.decode(), "public": pub_bytes.decode()}
        elif operation == 'sign':
            if not self.ecc_private_key:
                print("No ECC private key. Generate first.")
                return None
            msg = input("Enter message to sign: ")
            signature = self.ecc_private_key.sign(msg.encode(), ec.ECDSA(hashes.SHA256()))
            print("Signature (hex):", binascii.hexlify(signature).decode())
            return signature
        elif operation == 'verify':
            if not self.ecc_public_key:
                print("No ECC public key. Generate first.")
                return None
            msg = input("Enter message to verify: ")
            sig_hex = input("Enter signature (hex): ")
            signature = binascii.unhexlify(sig_hex)
            try:
                self.ecc_public_key.verify(signature, msg.encode(), ec.ECDSA(hashes.SHA256()))
                print("Signature verified: True")
            except InvalidSignature:
                print("Signature verified: False")
        else:
            print(f"ECC operation ({operation}) not implemented.")
            return None

    #  STEGANOGRAPHY 
    # Image steganography using LSB (hide/extract message in image)
    def image_steganography(self, image_path, message, mode='hide'):
        if mode == 'hide':
            img = Image.open(image_path)
            img = img.convert('RGB')
            data = message + chr(0)
            bits = ''.join([format(ord(c), '08b') for c in data])
            pixels = list(img.getdata())
            new_pixels = []
            bit_idx = 0
            for pixel in pixels:
                r, g, b = pixel
                if bit_idx < len(bits):
                    r = (r & ~1) | int(bits[bit_idx])
                    bit_idx += 1
                if bit_idx < len(bits):
                    g = (g & ~1) | int(bits[bit_idx])
                    bit_idx += 1
                if bit_idx < len(bits):
                    b = (b & ~1) | int(bits[bit_idx])
                    bit_idx += 1
                new_pixels.append((r, g, b))
            img.putdata(new_pixels)
            out_path = image_path + ".steg.png"
            img.save(out_path)
            print(f"Message hidden in {out_path}")
            return out_path
        elif mode == 'extract':
            img = Image.open(image_path)
            img = img.convert('RGB')
            pixels = list(img.getdata())
            bits = ""
            for pixel in pixels:
                for color in pixel:
                    bits += str(color & 1)
            chars = []
            for i in range(0, len(bits), 8):
                byte = bits[i:i+8]
                if len(byte) < 8:
                    break
                c = chr(int(byte, 2))
                if c == chr(0):
                    break
                chars.append(c)
            msg = ''.join(chars)
            print(f"Extracted message: {msg}")
            return msg
        else:
            print(f"Image steganography ({mode}) not supported.")
            return None

    # Audio steganography (not implemented)
    def audio_steganography(self, audio_path, message, mode='hide'):
        print(f"Audio steganography ({mode}) not yet implemented.")
        return None

    # Text steganography using whitespace (hide/extract message in text)
    def text_steganography(self, text, message, mode='hide'):
        if mode == 'hide':
            bits = ''.join(format(ord(c), '08b') for c in message + chr(0))
            stego = ""
            idx = 0
            for char in text:
                stego += char
                if idx < len(bits):
                    stego += ' ' if bits[idx] == '0' else '\t'
                    idx += 1
            print(f"Stego text:\n{stego}")
            return stego
        elif mode == 'extract':
            bits = ""
            for i in range(len(text)):
                if text[i] == ' ':
                    bits += '0'
                elif text[i] == '\t':
                    bits += '1'
            chars = []
            for i in range(0, len(bits), 8):
                byte = bits[i:i+8]
                if len(byte) < 8:
                    break
                c = chr(int(byte, 2))
                if c == chr(0):
                    break
                chars.append(c)
            msg = ''.join(chars)
            print(f"Extracted message: {msg}")
            return msg
        else:
            print(f"Text steganography ({mode}) not supported.")
            return None

    # File format steganography (not implemented)
    def file_format_steganography(self, file_path, message, mode='hide'):
        print(f"File format steganography ({mode}) not yet implemented.")
        return None

    #  ADVANCED ANALYSIS TOOLS 
    # Entropy analysis for randomness testing (Shannon entropy)
    def entropy_analysis(self, data):
        if not data:
            print("No data provided.")
            return None
        if isinstance(data, str):
            data = data.encode()
        freq = Counter(data)
        total = len(data)
        entropy = -sum((count/total) * math.log2(count/total) for count in freq.values())
        print(f"Entropy: {entropy:.2f} bits/byte")
        return entropy

    # N-gram analysis for language detection/statistics
    def ngram_analysis(self, text, n=2):
        text = ''.join([c.lower() for c in text if c.isalpha()])
        ngrams = Counter([text[i:i+n] for i in range(len(text)-n+1)])
        print(f"Top {n}-grams:")
        for ng, count in ngrams.most_common(10):
            print(f"{ng}: {count}")
        return ngrams

    # Markov chain analysis for pattern recognition
    def markov_chain_analysis(self, text):
        text = ''.join([c.lower() for c in text if c.isalpha()])
        transitions = {}
        for i in range(len(text)-1):
            pair = (text[i], text[i+1])
            transitions[pair] = transitions.get(pair, 0) + 1
        print("Top transitions:")
        for k, v in sorted(transitions.items(), key=lambda x: -x[1])[:10]:
            print(f"{k}: {v}")
        return transitions

    # Visualization tools for frequency analysis (ASCII bar chart)
    def frequency_visualization(self, text):
        counter = Counter([c.upper() for c in text if c.isalpha()])
        total = sum(counter.values())
        for letter in string.ascii_uppercase:
            freq = counter.get(letter, 0)
            bar = '█' * int((freq/total)*40) if total else ''
            print(f"{letter}: {bar} ({freq})")
        return counter

    #  QUANTUM-RESISTANT CRYPTOGRAPHY 

    # Lattice-based cryptography (NTRU, scaffold)
    def lattice_based_crypto(self, operation='keygen'):
        print(f"Lattice-based crypto ({operation}) not yet implemented (NTRU scaffold).")
        return None

    # Hash-based signature (XMSS, scaffold)
    def hash_based_signature(self, operation='sign'):
        print(f"Hash-based signature ({operation}) not yet implemented (XMSS scaffold).")
        return None

    # Code-based cryptography (McEliece, scaffold)
    def code_based_crypto(self, operation='keygen'):
        print(f"Code-based crypto ({operation}) not yet implemented (McEliece scaffold).")
        return None

    # Post-quantum key exchange (Kyber, scaffold)
    def post_quantum_key_exchange(self, protocol='kyber'):
        print(f"Post-quantum key exchange ({protocol}) not yet implemented (Kyber scaffold).")
        return None

    #  SECURITY CONSIDERATIONS 
    # Constant-time comparison for sensitive data (prevents timing attacks)
    def constant_time_compare(self, val1, val2):
        return py_hmac.compare_digest(val1, val2)

    # Store key securely in memory (optionally to file)
    def secure_key_store(self, key_name, key_value):
        self.secure_storage[key_name] = key_value

    # Load key from secure storage
    def secure_key_load(self, key_name):
        return self.secure_storage.get(key_name)

    #  UTILITIES 
    # Generate a random key of given type and length
    def generate_random_key(self, length=10, key_type="alpha"):
        if key_type == "alpha":
            chars = string.ascii_letters
        elif key_type == "alphanum":
            chars = string.ascii_letters + string.digits
        else:
            chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))

    # Reverse the input text
    def reverse_text(self, text):
        return text[::-1]

    # Show basic statistics about the text
    def text_statistics(self, text):
        print(f"Length: {len(text)}")
        print(f"Alphabetic: {sum(c.isalpha() for c in text)}")
        print(f"Digits: {sum(c.isdigit() for c in text)}")
        print(f"Whitespace: {sum(c.isspace() for c in text)}")
        print(f"Unique chars: {len(set(text))}")

    # Simulate timing attack by measuring function execution time
    def timing_attack_simulation(self, func, *args, **kwargs):
        import time
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"Execution time: {(end-start)*1e6:.2f} us")
        return result

    # Differential cryptanalysis scaffold
    def differential_cryptanalysis(self, cipher_type='aes'):
        print(f"Differential cryptanalysis for {cipher_type} not yet implemented (scaffold).")
        return None

def main():
    crypto = IntermediateCryptoTool()
    
    while True:
        try:
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}              ENCRYPTION & DECRYPTION TOOL{Style.RESET_ALL}")
            print(f"{Fore.RED}                 Author: SOUMIT SANTRA {Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print("\nCLASSIC CIPHERS:")
            print("-"*20)
            print("1.  Caesar Cipher (Enhanced)")
            print("2.  Vigenère Cipher") 
            print("3.  Playfair Cipher")
            print("4.  Rail Fence Cipher")
            print("5.  Atbash Cipher")
            print("6.  ROT13")
            
            print("\nENCODING/DECODING:")
            print("-"*20)
            print("7.  Base64")
            print("8.  Hexadecimal")
            print("9.  Binary")
            print("10. Morse Code")
            
            print("\nHASH FUNCTIONS:")
            print("-"*20)
            print("11. Hash Text (MD5, SHA1, SHA256, etc.)")
            
            print("\nANALYSIS TOOLS:")
            print("-"*20)
            print("12. Frequency Analysis")
            print("13. Language Detection")
            print("14. Text Statistics")
            
            print("\nBRUTE FORCE TOOLS:")
            print("-"*20)
            print("15. Caesar Brute Force")
            print("16. Vigenère Key Length Analysis")
            
            print("\nUTILITIES:")
            print("-"*20)
            print("17. Generate Random Key")
            print("18. Reverse Text")
            
            print("\nMODERN ENCRYPTION:")
            print("-"*20)
            print("19. Fernet (Encrypt/Decrypt)")
            print("20. RSA (Encrypt/Decrypt)")
            print("21. Generate New Keys")
            
            print("\nCRYPTOANALYSIS & ADVANCED BREAKING:")
            print("-"*20)
            print("22. Kasiski Examination (Vigenère)")
            print("23. Chi-squared Substitution Analysis")
            print("24. Dictionary Attack (Modern Encryption)")
            print("25. Side-channel Simulation")
            print("26. Differential Cryptanalysis")
            
            print("\nMODERN CRYPTOGRAPHIC PROTOCOLS:")
            print("-"*20)
            print("27. Digital Signature")
            print("28. Key Exchange Protocol")
            print("29. HMAC (MAC)")
            print("30. Password-based Encryption")
            print("31. Elliptic Curve Cryptography")
            
            print("\nSTEGANOGRAPHY & DATA HIDING:")
            print("-"*20)
            print("32. Image Steganography")
            print("33. Audio Steganography")
            print("34. Text Steganography")
            print("35. File Format Steganography")
            
            print("\nADVANCED ANALYSIS TOOLS:")
            print("-"*20)
            print("36. Entropy Analysis")
            print("37. N-gram Analysis")
            print("38. Markov Chain Analysis")
            print("39. Statistical Cipher Identification")
            print("40. Frequency Visualization")
            
            print("\nQUANTUM-RESISTANT CRYPTOGRAPHY:")
            print("-"*20)
            print("41. Lattice-based Crypto")
            print("42. Hash-based Signature")
            print("43. Code-based Crypto")
            print("44. Post-Quantum Key Exchange")
            print("-"*20)
            print("45. Exit")
            print("-"*70)
            
            choice = input("Enter your choice (1-45): ").strip()
            
            try:
                if choice == "1":
                    operation = input("Encrypt or Decrypt? (e/d): ").lower()
                    text = input("Enter text: ")
                    shift = int(input("Enter shift value: "))
                    if operation == 'e':
                        result = crypto.caesar_encrypt(text, shift)
                        print(f" Encrypted: {result}")
                    else:
                        result = crypto.caesar_decrypt(text, shift)
                        print(f" Decrypted: {result}")
                
                elif choice == "2":
                    operation = input("Encrypt or Decrypt? (e/d): ").lower()
                    text = input("Enter text: ")
                    key = input("Enter key: ")
                    if operation == 'e':
                        result = crypto.vigenere_encrypt(text, key)
                        print(f" Encrypted: {result}")
                    else:
                        result = crypto.vigenere_decrypt(text, key)
                        print(f" Decrypted: {result}")
                
                elif choice == "3":
                    operation = input("Encrypt or Decrypt? (e/d): ").lower()
                    text = input("Enter text: ")
                    key = input("Enter key: ")
                    if operation == 'e':
                        result = crypto.playfair_encrypt(text, key)
                        print(f" Encrypted: {result}")
                    else:
                        result = crypto.playfair_decrypt(text, key)
                        print(f" Decrypted: {result}")
                
                elif choice == "4":
                    operation = input("Encrypt or Decrypt? (e/d): ").lower()
                    text = input("Enter text: ")
                    rails = int(input("Enter number of rails: "))
                    if operation == 'e':
                        result = crypto.rail_fence_encrypt(text, rails)
                        print(f" Encrypted: {result}")
                    else:
                        result = crypto.rail_fence_decrypt(text, rails)
                        print(f" Decrypted: {result}")
                
                elif choice == "5":
                    operation = input("Encrypt or Decrypt? (e/d): ").lower()
                    text = input("Enter text: ")
                    result = crypto.atbash_encrypt(text)
                    print(f" Atbash result: {result}")
                
                elif choice == "6":
                    text = input("Enter text: ")
                    result = crypto.rot13_encrypt(text)
                    print(f" ROT13 result: {result}")
                
                elif choice == "7":
                    operation = input("Encode or Decode? (e/d): ").lower()
                    text = input("Enter text: ")
                    if operation == 'e':
                        result = crypto.base64_encode(text)
                        print(f" Base64 encoded: {result}")
                    else:
                        result = crypto.base64_decode(text)
                        print(f" Base64 decoded: {result}")
                
                elif choice == "8":
                    operation = input("Encode or Decode? (e/d): ").lower()
                    text = input("Enter text: ")
                    if operation == 'e':
                        result = crypto.hex_encode(text)
                        print(f" Hex encoded: {result}")
                    else:
                        result = crypto.hex_decode(text)
                        print(f" Hex decoded: {result}")
                
                elif choice == "9":
                    operation = input("Encode or Decode? (e/d): ").lower()
                    text = input("Enter text: ")
                    if operation == 'e':
                        result = crypto.binary_encode(text)
                        print(f" Binary encoded: {result}")
                    else:
                        result = crypto.binary_decode(text)
                        print(f" Binary decoded: {result}")
                
                elif choice == "10":
                    operation = input("Encode or Decode? (e/d): ").lower()
                    text = input("Enter text: ")
                    if operation == 'e':
                        result = crypto.morse_encode(text)
                        print(f" Morse encoded: {result}")
                    else:
                        result = crypto.morse_decode(text)
                        print(f" Morse decoded: {result}")
                
                elif choice == "11":
                    text = input("Enter text to hash: ")
                    algorithm = input("Enter algorithm (md5/sha1/sha224/sha256/sha384/sha512): ").lower()
                    result = crypto.hash_text(text, algorithm)
                    print(f" {algorithm.upper()} hash: {result}")
                
                elif choice == "12":
                    text = input("Enter text for frequency analysis: ")
                    crypto.frequency_analysis(text)
                
                elif choice == "13":
                    text = input("Enter text for language detection: ")
                    result = crypto.detect_language(text)
                    print(f" Language detection: {result}")
                
                elif choice == "14":
                    text = input("Enter text for statistics: ")
                    crypto.text_statistics(text)
                
                elif choice == "15":
                    text = input("Enter encrypted text for Caesar brute force: ")
                    crypto.brute_force_caesar(text)
                
                elif choice == "16":
                    text = input("Enter encrypted text for Vigenère analysis: ")
                    crypto.brute_force_vigenere_key_length(text)
                
                elif choice == "17":
                    length = int(input("Enter key length (default 10): ") or "10")
                    key_type = input("Key type (alpha/alphanum/all) [default: alpha]: ").lower() or "alpha"
                    key = crypto.generate_random_key(length, key_type)
                    print(f" Random key: {key}")
                
                elif choice == "18":
                    text = input("Enter text to reverse: ")
                    result = crypto.reverse_text(text)
                    print(f" Reversed: {result}")
                
                elif choice == "19":
                    op = input("Encrypt or Decrypt? (e/d): ").lower()
                    if op == "e":
                        text = input("Enter text for Fernet encryption: ")
                        try:
                            result = crypto.fernet_encrypt(text)
                            print(f" Fernet encrypted: {result}")
                        except Exception as e:
                            print(f" Error: {e}")
                    elif op == "d":
                        text = input("Enter Fernet encrypted text: ")
                        try:
                            result = crypto.fernet_decrypt(text)
                            print(f" Fernet decrypted: {result}")
                        except Exception as e:
                            print(f" Error: {e}")
                    else:
                        print(" Invalid operation. Use 'e' or 'd'.")
                elif choice == "20":
                    op = input("Encrypt or Decrypt? (e/d): ").lower()
                    if op == "e":
                        text = input("Enter text for RSA encryption: ")
                        public_key = input("Enter public key (leave blank for default key): ")
                        try:
                            result = crypto.rsa_encrypt(text, public_key if public_key else None)
                            print(f" RSA encrypted: {result}")
                        except Exception as e:
                            print(f" Error: {e}")
                    elif op == "d":
                        text = input("Enter RSA encrypted hex string: ")
                        private_key = input("Enter private key (leave blank for default key): ")
                        try:
                            result = crypto.rsa_decrypt(text, private_key if private_key else None)
                            print(f" RSA decrypted: {result}")
                        except Exception as e:
                            print(f" Error: {e}")
                    else:
                        print(" Invalid operation. Use 'e' or 'd'.")
                elif choice == "21":
                    size = int(input("Enter key size (default 2048): ") or "2048")
                    try:
                        keys = crypto.generate_rsa_keypair(size)
                        print("Generated RSA Key Pair:")
                        print("-" * 50)
                        print(f"Private Key:\n{keys['private']}")
                        print(f"Public Key:\n{keys['public']}")
                    except Exception as e:
                        print(f" Error: {e}")

                elif choice == "22":
                    text = input("Enter ciphertext for Kasiski examination: ")
                    crypto.kasiski_examination(text)
                elif choice == "23":
                    text = input("Enter ciphertext for chi-squared analysis: ")
                    crypto.chi_squared_substitution(text)
                elif choice == "24":
                    text = input("Enter ciphertext for dictionary attack: ")
                    attack_type = input("Type (fernet/rsa): ").lower()
                    crypto.dictionary_attack(text, attack_type)
                elif choice == "25":
                    cipher_type = input("Cipher type (aes/rsa): ").lower()
                    crypto.side_channel_simulation(cipher_type)
                elif choice == "26":
                    cipher_type = input("Cipher type (aes): ").lower()
                    crypto.differential_cryptanalysis(cipher_type)
                elif choice == "27":
                    msg = input("Enter message for digital signature: ")
                    algo = input("Algorithm (rsa/ecdsa/eddsa): ").lower()
                    crypto.digital_signature(msg, algo)
                elif choice == "28":
                    protocol = input("Protocol (dh/ecdh): ").lower()
                    crypto.key_exchange(protocol)
                elif choice == "29":
                    msg = input("Enter message for HMAC: ")
                    key = input("Enter key: ")
                    algo = input("Algorithm (sha256/sha512): ").lower()
                    crypto.hmac_mac(msg, key, algo)
                elif choice == "30":
                    password = input("Enter password: ")
                    data = input("Enter data to encrypt: ")
                    algo = input("Algorithm (pbkdf2/argon2/scrypt): ").lower()
                    crypto.password_based_encryption(password, data, algo)
                elif choice == "31":
                    op = input("Operation (keygen/sign/verify): ").lower()
                    curve = input("Curve (secp256k1): ").lower()
                    crypto.elliptic_curve_crypto(op, curve)
                elif choice == "32":
                    img = input("Image path: ")
                    msg = input("Message: ")
                    mode = input("Mode (hide/extract): ").lower()
                    crypto.image_steganography(img, msg, mode)
                elif choice == "33":
                    audio = input("Audio path: ")
                    msg = input("Message: ")
                    mode = input("Mode (hide/extract): ").lower()
                    crypto.audio_steganography(audio, msg, mode)
                elif choice == "34":
                    text = input("Text: ")
                    msg = input("Message: ")
                    mode = input("Mode (hide/extract): ").lower()
                    crypto.text_steganography(text, msg, mode)
                elif choice == "35":
                    file = input("File path: ")
                    msg = input("Message: ")
                    mode = input("Mode (hide/extract): ").lower()
                    crypto.file_format_steganography(file, msg, mode)
                elif choice == "36":
                    data = input("Enter data for entropy analysis: ")
                    crypto.entropy_analysis(data)
                elif choice == "37":
                    text = input("Enter text for n-gram analysis: ")
                    n = int(input("N value (default 2): ") or "2")
                    crypto.ngram_analysis(text, n)
                elif choice == "38":
                    text = input("Enter text for Markov chain analysis: ")
                    crypto.markov_chain_analysis(text)
                elif choice == "39":
                    text = input("Enter ciphertext for statistical cipher identification: ")
                    crypto.statistical_cipher_id(text)
                elif choice == "40":
                    text = input("Enter text for frequency visualization: ")
                    crypto.frequency_visualization(text)
                elif choice == "41":
                    op = input("Operation (keygen/encrypt/decrypt): ").lower()
                    crypto.lattice_based_crypto(op)
                elif choice == "42":
                    op = input("Operation (sign/verify): ").lower()
                    crypto.hash_based_signature(op)
                elif choice == "43":
                    op = input("Operation (keygen/encrypt/decrypt): ").lower()
                    crypto.code_based_crypto(op)
                elif choice == "44":
                    protocol = input("Protocol (kyber): ").lower()
                    crypto.post_quantum_key_exchange(protocol)
                elif choice == "45":
                    print(" Goodbye! Stay secure!")
                    break
                else:
                    print(" Invalid choice. Please enter a number between 1 and 45.")
            except ValueError as e:
                print(f" Invalid input: {e}")
            except Exception as e:
                print(f" An error occurred: {e}")
        except KeyboardInterrupt:
            print("\n Interrupted by user. Exiting.")
            break
        except Exception as e:
            print(f" Fatal error: {e}")

if __name__ == "__main__":

    main()
