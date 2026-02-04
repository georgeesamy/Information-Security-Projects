#============================== AES 256 CIPHER ==============================
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def aes_encrypt(text, key):
    key = key.ljust(32)[:32].encode()
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    encrypted = cipher.encrypt(nonce, text.encode(), None)
    return base64.b64encode(nonce + encrypted).decode()

def aes_decrypt(token, key):
    key = key.ljust(32)[:32].encode()
    data = base64.b64decode(token)
    cipher = AESGCM(key)
    return cipher.decrypt(data[:12], data[12:], None).decode()

# Test
enc = aes_encrypt("MyPassword123", "secretkey")
print("Encrypted:", enc)
print("Decrypted:", aes_decrypt(enc, "secretkey"))


#============================== PLAYFAIR CIPHER ==============================
def playfair_encrypt(text, key):
    # Build 5x5 table
    key = key.upper().replace("J", "I")
    table = "".join(dict.fromkeys(key + "ABCDEFGHIKLMNOPQRSTUVWXYZ"))
    
    # Prepare text
    text = text.upper().replace("J", "I").replace(" ", "")
    
    # Make pairs
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) and text[i+1] != a else "X"
        pairs.append((a, b))
        i += 1 if b == "X" else 2
    
    # Encrypt pairs
    result = ""
    for a, b in pairs:
        r1, c1 = divmod(table.index(a), 5)
        r2, c2 = divmod(table.index(b), 5)
        
        if r1 == r2:  # Same row
            result += table[r1*5 + (c1+1)%5] + table[r2*5 + (c2+1)%5]
        elif c1 == c2:  # Same column
            result += table[((r1+1)%5)*5 + c1] + table[((r2+1)%5)*5 + c2]
        else:  # Rectangle
            result += table[r1*5 + c2] + table[r2*5 + c1]
    
    return result

print("Playfair:", playfair_encrypt("Accepts", "Monarchy"))


#============================== VIGENERE CIPHER ==============================
def vigenere_encrypt(text, key):
    text = text.upper()
    key = key.upper()
    result = ""
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            encrypted_char = chr((ord(char) - 65 + shift) % 26 + 65)
            result += encrypted_char
            key_index += 1
        else:
            result += char
    
    return result

print("Vigenere:", vigenere_encrypt("HELLO", "KEY"))





