# des/modes.py
from typing import List
from .des_core import DES
from copy import deepcopy

# ===========
# Padding: PKCS#7
# ===========
def pad(data: bytes, block_size: int = 8) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    return data + bytes([padding_len]) * padding_len

def unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data:
        return b""
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size or padding_len > len(data):
        # Invalid padding, return as is (could raise error alternatively)
        return data
    return data[:-padding_len]

# ===========
# Base Mode
# ===========
class _BaseMode:
    def __init__(self, des_engine: DES = None):
        self.des = des_engine
        if des_engine:
            self.block_size_bytes = self.des.block_size // 8
            # Use deepcopy for iv to avoid mutation side-effects
            self.iv = deepcopy(self.des.iv)
        else:
            self.block_size_bytes = 0
            self.iv = None
            
    def set_des_engine(self, des_engine: DES):
        self.des = des_engine
        self.block_size_bytes = self.des.block_size // 8
        self.iv = deepcopy(self.des.iv)

    def _get_blocks(self, data: bytes) -> List[bytes]:
        if not self.block_size_bytes:
            raise ValueError("DES engine or block size not set")
        return [data[i:i+self.block_size_bytes] for i in range(0, len(data), self.block_size_bytes)]

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        raise NotImplementedError()

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        raise NotImplementedError()


# ===========
# ECB Mode
# ===========
class ECB(_BaseMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")

        padded = pad(plaintext, self.block_size_bytes)
        encrypted = [self.des.encrypt_block(b) for b in self._get_blocks(padded)]
        return b''.join(encrypted)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")

        decrypted = [self.des.decrypt_block(b) for b in self._get_blocks(ciphertext)]
        return unpad(b''.join(decrypted), self.block_size_bytes)


# ===========
# CBC Mode
# ===========
class CBC(_BaseMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        if not self.iv:
            raise ValueError("IV must be set for CBC mode")

        padded = pad(plaintext, self.block_size_bytes)
        encrypted_blocks = []
        previous_block = self.iv

        for block in self._get_blocks(padded):
            xored = bytes(p ^ c for p, c in zip(block, previous_block))
            cipher_block = self.des.encrypt_block(xored)
            encrypted_blocks.append(cipher_block)
            previous_block = cipher_block
        
        return b''.join(encrypted_blocks)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        if not self.iv:
            raise ValueError("IV must be set for CBC mode")

        decrypted_blocks = []
        previous_block = self.iv

        for block in self._get_blocks(ciphertext):
            decrypted_block = self.des.decrypt_block(block)
            plain_block = bytes(d ^ p for d, p in zip(decrypted_block, previous_block))
            decrypted_blocks.append(plain_block)
            previous_block = block
        
        return unpad(b''.join(decrypted_blocks), self.block_size_bytes)

# ===========
# CFB Mode
# ===========
class CFB(_BaseMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        if not self.iv:
            raise ValueError("IV must be set for CFB mode")

        padded = pad(plaintext, self.block_size_bytes)
        encrypted_blocks = []
        prev_cipher = self.iv

        for block in self._get_blocks(padded):
            encrypted_iv = self.des.encrypt_block(prev_cipher)
            cipher_block = bytes(p ^ e for p, e in zip(block, encrypted_iv))
            encrypted_blocks.append(cipher_block)
            prev_cipher = cipher_block
        
        return b''.join(encrypted_blocks)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        if not self.iv:
            raise ValueError("IV must be set for CFB mode")

        decrypted_blocks = []
        prev_cipher = self.iv

        for block in self._get_blocks(ciphertext):
            encrypted_iv = self.des.encrypt_block(prev_cipher)
            plain_block = bytes(c ^ e for c, e in zip(block, encrypted_iv))
            decrypted_blocks.append(plain_block)
            prev_cipher = block
        
        return unpad(b''.join(decrypted_blocks), self.block_size_bytes)

# ===========
# OFB Mode
# ===========
class OFB(_BaseMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        if not self.iv:
            raise ValueError("IV must be set for OFB mode")

        padded = pad(plaintext, self.block_size_bytes)
        encrypted_blocks = []
        feedback = self.iv

        for block in self._get_blocks(padded):
            output_block = self.des.encrypt_block(feedback)
            cipher_block = bytes(p ^ o for p, o in zip(block, output_block))
            encrypted_blocks.append(cipher_block)
            feedback = output_block
        
        return b''.join(encrypted_blocks)

    def decrypt(self, ciphertext: bytes) -> bytes:
        # OFB decryption same as encryption
        return self.encrypt(ciphertext)

# ===========
# CTR Mode
# ===========
class CTR(_BaseMode):
    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.des:
            raise ValueError("DES engine not set")
        if not self.iv:
            raise ValueError("IV must be set for CTR mode")

        padded = pad(plaintext, self.block_size_bytes)
        encrypted_blocks = []
        counter = int.from_bytes(self.iv, 'big')
        block_len = self.block_size_bytes

        for block in self._get_blocks(padded):
            counter_block = counter.to_bytes(block_len, 'big')
            output_block = self.des.encrypt_block(counter_block)
            cipher_block = bytes(p ^ o for p, o in zip(block, output_block))
            encrypted_blocks.append(cipher_block)
            counter += 1
        
        return b''.join(encrypted_blocks)

    def decrypt(self, ciphertext: bytes) -> bytes:
        # CTR decryption same as encryption
        return self.encrypt(ciphertext)
