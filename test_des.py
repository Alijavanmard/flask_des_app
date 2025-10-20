from des.des_core import encrypt_text, decrypt_text

import des.des_core
print("⚙️ des_core loaded from →", des.des_core.__file__)


msg = "HELLOALI"
key = "MYSECRET"

print("🧪 Running DES-like Encryption Test...\n")
cipher = encrypt_text(msg, key)
plain = decrypt_text(cipher, key)
print("🔒 Cipher bits:\n", cipher)
print("🔓 Decrypted:\n", plain)
