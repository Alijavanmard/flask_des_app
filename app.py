# -----------------------------------------------
# app.py — Final Stable Release For AliAkbar
# رمزنگاری DES با پنج مود عملیاتی (ECB، CBC، CFB، OFB، CTR)
# نسخه نهایی با UX ایمن‌تر و جلوگیری از ورودی‌های ناسازگار
# -----------------------------------------------

import os, re, traceback
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from des.des_core import DES
from des.modes import ECB, CBC, CFB, OFB, CTR

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ---------------------- #
# Helper Functions       #
# ---------------------- #
def is_ascii(s: str) -> bool:
    return bool(re.fullmatch(r"[ -~]*", s))  # printable ASCII range

def error_response(context, msg, code=400, as_json=False):
    context["result"] = msg
    if as_json:
        return jsonify({"error": msg}), code
    return render_template("index.html", **context)

# ---------------------- #
# Home Route             #
# ---------------------- #
@app.route("/", methods=["GET"])
def index():
    context = session.pop(
        "context",
        {
            "plaintext": "",
            "key": "",
            "rounds": 16,
            "block_size": 64,
            "key_length": 64,
            "mode": "CBC",
            "operation": "encrypt",
            "iv": "12345678",
            "result": "",
        },
    )
    return render_template("index.html", **context)

# ---------------------- #
# Process Route (POST)   #
# ---------------------- #
@app.route("/process", methods=["POST"])
def process():
    data = request.get_json(force=True) if request.is_json else request.form

    context = {
        "plaintext": data.get("plaintext", "").strip(),
        "key": data.get("key", "").strip(),
        "iv": data.get("iv", "").strip(),
        "rounds": int(data.get("rounds", 16)),
        "block_size": int(data.get("block_size", 64)),
        "key_length": int(data.get("key_length", 64)),
        "mode": data.get("mode", "CBC").upper(),
        "operation": data.get("operation") or data.get("action") or "encrypt",
        "result": "",
    }

    # ---------------------- #
    # ✳️ ورودی‌ها و اعتبارسنجی‌ها
    # ---------------------- #
    for f in ["plaintext", "key", "iv"]:
        if not is_ascii(context[f]):
            return error_response(
                context,
                f"⚠️ خطا: مقدار «{f}» فقط باید شامل حروف و علائم انگلیسی باشد.",
                400,
                request.is_json,
            )

    pt, key, iv = context["plaintext"], context["key"], context["iv"]
    rounds, mode = context["rounds"], context["mode"]

    if not pt or not key:
        return error_response(context, "⚠️ متن یا کلید نمی‌تواند خالی باشد.", 400, request.is_json)

    # محدود کردن BlockSize به 64 جهت DES
    context["block_size"] = 64

    # محدودکردن Roundها
    if rounds < 8:
        context["rounds"] = 8
    elif rounds > 32:
        context["rounds"] = 32

    # بررسی طول IV در حالت‌هایی که نیاز است
    needs_iv = mode in ("CBC", "CFB", "OFB", "CTR")
    if needs_iv:
        if not iv or len(iv) != 8:
            return error_response(
                context, "⚠️ طول IV باید دقیقاً ۸ کاراکتر باشد.", 400, request.is_json
            )
    else:
        iv = None  # برای ECB حذف می‌شود

    try:
        des_engine = DES(key.encode(), iv=iv.encode() if iv else None, mode=mode)

        # انتخاب مود
        mode_map = {"ECB": ECB, "CBC": CBC, "CFB": CFB, "OFB": OFB, "CTR": CTR}
        ctx = mode_map[mode](des_engine)

        if context["operation"] == "encrypt":
            result = ctx.encrypt(pt.encode()).hex()
        else:
            result = ctx.decrypt(bytes.fromhex(pt)).decode(errors="ignore")

        context["result"] = result

        if request.is_json:
            return jsonify({"result": result, "mode": mode, "operation": context["operation"]})

        session["context"] = context
        return redirect(url_for("index"))

    except Exception as e:
        traceback.print_exc()
        return error_response(context, f"❌ خطا: {e}", 500, request.is_json)


# ---------------------- #
# API Endpoints          #
# ---------------------- #
@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(force=True)
    plaintext, key = data.get("plaintext", ""), data.get("key", "")
    iv = data.get("iv", "")
    mode = data.get("mode", "CBC").upper()
    try:
        des_engine = DES(key.encode(), iv=iv.encode() if iv else None, mode=mode)
        ctx = {"ECB": ECB, "CBC": CBC, "CFB": CFB, "OFB": OFB, "CTR": CTR}[mode](des_engine)
        result = ctx.encrypt(plaintext.encode()).hex()
        return jsonify({"ciphertext": result, "mode": mode})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json(force=True)
    ciphertext, key = data.get("ciphertext", ""), data.get("key", "")
    iv = data.get("iv", "")
    mode = data.get("mode", "CBC").upper()
    try:
        des_engine = DES(key.encode(), iv=iv.encode() if iv else None, mode=mode)
        ctx = {"ECB": ECB, "CBC": CBC, "CFB": CFB, "OFB": OFB, "CTR": CTR}[mode](des_engine)
        result = ctx.decrypt(bytes.fromhex(ciphertext)).decode(errors="ignore")
        return jsonify({"plaintext": result, "mode": mode})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
    app.run(debug=True, port=5000)
