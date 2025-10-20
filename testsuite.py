# testsuite.py — Final Stable Version
# Ali Akbar Davanmard • 2025-10-20

import itertools
from datetime import datetime
from des import modes, des_core

# Fixed sample plaintext / key pattern
sample_plaintext = "HelloAliAkbarDES"

# Parameter spaces
modes_list = ["ECB", "CBC", "CFB", "OFB", "CTR"]
block_sizes = [32, 64, 128]
key_lengths = [32, 64, 128]
rounds_list = [8, 12, 16]

report_lines = []
total_tests = 0
passed_tests = 0

print("🔍 Starting DES Test Harness...\n")

for mode_name, block_size, key_length, rounds in itertools.product(modes_list, block_sizes, key_lengths, rounds_list):
    total_tests += 1
    try:
        # --- Generate valid key/IV lengths ---
        sample_key = "AliKey12345678901234567890"[: key_length // 8]
        sample_iv = "?" * (block_size // 8)

        # --- Encode as bytes ---
        key = sample_key.encode("utf-8")
        iv = sample_iv.encode("utf-8")
        plaintext_bytes = sample_plaintext.encode("utf-8")

        # --- Initialize DES ---
        mode_class = getattr(modes, mode_name)
        des = des_core.DES(
            key=key,
            mode=mode_class(),
            block_size=block_size,
            rounds=rounds,
            iv=iv
        )

        # --- Encrypt & Decrypt ---
        encrypted = des.encrypt(plaintext_bytes)
        decrypted = des.decrypt(encrypted)

        # --- Decode bytes to string ---
        decrypted_text = decrypted.decode("utf-8", errors="ignore")

        ok = decrypted_text == sample_plaintext
        status = "✅ PASS" if ok else "❌ FAIL"
        if ok:
            passed_tests += 1
        print(f"[{total_tests}/135] Mode={mode_name}, Block={block_size}, KeyLen={key_length}, Rounds={rounds} → {status}")
        report_lines.append(f"{mode_name},{block_size},{key_length},{rounds},{status}")

    except Exception as e:
        print(f"[{total_tests}/135] Mode={mode_name}, Block={block_size}, KeyLen={key_length}, Rounds={rounds} → ❌ ERROR: {e}")
        report_lines.append(f"{mode_name},{block_size},{key_length},{rounds},ERROR:{e}")

# --- Summary ---
print("\n=============================")
print(f"Completed {total_tests} tests")
print(f"Passed: {passed_tests} / {total_tests}")
print(f"Failed: {total_tests - passed_tests}")
print(f"Timestamp: {datetime.now()}\n")

report_path = r"C:\Users\AliAkbar\Desktop\flask_des_app\test_report.txt"
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(report_lines))
print(f"📄 Test report saved to: {report_path}")
