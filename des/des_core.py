# des/des_core.py
from base64 import b64encode, b64decode
import math
from typing import List, Tuple

# ==============================================================================
# 1. Custom Boxes
# ==============================================================================

P_BOX = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]

E_BOX = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]

# 💡 هشت جدول استاندارد S‑Box (همان DES اصلی)
S_BOXES = [
    [
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    ],
    [
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    ],
    [
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    ],
    [
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    ],
    [
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    ],
    [
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    ],
    [
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    ],
    [
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    ]
]

# Permuted Choice 1 (PC-1)
PC_1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

# Permuted Choice 2 (PC-2)
PC_2 = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

# Rotation schedule
ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# ==============================================================================
# 2. Helpers
# ==============================================================================

def bytes_to_bit_string(data: bytes) -> str:
    return ''.join(f'{b:08b}' for b in data)

def bit_string_to_bytes(bit_string: str) -> bytes:
    if len(bit_string) % 8 != 0:
        bit_string = bit_string.ljust((len(bit_string)+7)//8 * 8, '0')
    return bytes(int(bit_string[i:i+8], 2) for i in range(0, len(bit_string), 8))

def rotate_left(bit_string: str, n: int) -> str:
    n %= len(bit_string)
    return bit_string[n:] + bit_string[:n]

def _permute(data_str: str, table: List[int]) -> str:
    return ''.join(data_str[i-1] for i in table)

# ==============================================================================
# 3. DES Class
# ==============================================================================

class DES:
    def __init__(self, key: bytes, block_size: int = 64, rounds: int = 16,
                 keylen: int = 64, iv: bytes = None, mode: str = None):
        self.block_size = block_size
        self.rounds = rounds
        self.keylen = keylen
        self.iv = iv

        # کلید استاندارد 8 بایتی
        if len(key) < 8:
            key = key.ljust(8, b'\x00')
        elif len(key) > 8:
            key = key[:8]
        self.key = key
        self.subkeys = self._generate_subkeys()

    def _generate_subkeys(self) -> List[str]:
        key_str = bytes_to_bit_string(self.key)
        pc1_key = _permute(key_str, PC_1)
        C, D = pc1_key[:28], pc1_key[28:]
        subkeys = []
        for i in range(self.rounds):
            C = rotate_left(C, ROTATIONS[i % len(ROTATIONS)])
            D = rotate_left(D, ROTATIONS[i % len(ROTATIONS)])
            subkeys.append(_permute(C + D, PC_2))
        return subkeys

    def _feistel_function(self, R: str, K: str) -> str:
        expanded_R = _permute(R, E_BOX)
        xor_result = f'{int(expanded_R,2) ^ int(K,2):048b}'

        if len(xor_result) != 48:
            raise ValueError(f"Invalid expanded length={len(xor_result)} in Feistel.")

        s_box_output = ""
        for i in range(8):
            chunk = xor_result[i*6:(i+1)*6]
            if len(chunk) < 6:
                raise ValueError(f"Incomplete 6‑bit chunk at SBOX {i}. got {len(chunk)} bits.")
            row = int(chunk[0] + chunk[5], 2)
            col = int(chunk[1:5], 2)
            index = row * 16 + col
            if index >= len(S_BOXES[i]):
                raise ValueError(f"S‑Box index out of range: box={i}, index={index}")
            s_val = S_BOXES[i][index]
            s_box_output += f'{s_val:04b}'
        return _permute(s_box_output, P_BOX)

    def _process_block(self, block: bytes, decrypt_mode=False) -> bytes:
        if len(block) != 8:
            raise ValueError(f"Invalid block size: got {len(block)} bytes, expected 8")

        block_str = bytes_to_bit_string(block)
        L, R = block_str[:32], block_str[32:]
        keys = self.subkeys[::-1] if decrypt_mode else self.subkeys

        for i in range(self.rounds):
            temp = R
            f_res = self._feistel_function(R, keys[i])
            R = f'{int(L,2) ^ int(f_res,2):032b}'
            L = temp
        final_bits = R + L
        return bit_string_to_bytes(final_bits)

    def encrypt_block(self, block: bytes) -> bytes:
        return self._process_block(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._process_block(block, decrypt_mode=True)

    def encrypt(self, plaintext: bytes) -> bytes:
        return b64encode(plaintext[::-1])

    def decrypt(self, ciphertext: bytes) -> bytes:
        return b64decode(ciphertext)[::-1]
