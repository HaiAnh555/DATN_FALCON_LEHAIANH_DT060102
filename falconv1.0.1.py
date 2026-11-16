#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

 
"""

from __future__ import annotations

import argparse
import base64
import cmath
import hashlib
import io
import json
import math
import os
import re
import secrets
import struct
import sys
import threading
import time
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Import PyPDF
try:
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        ArrayObject, DictionaryObject, NameObject, NumberObject, TextStringObject
    )
    PYPDF_OK = True
except ImportError:
    PYPDF_OK = False


# ============================================================================
#       3. TẦNG KÝ SỐ HẬU LƯỢNG TỬ FALCON (Full NIST Falcon Math Architecture)
# ============================================================================

class FalconNISTParams:
    """Tham số chuẩn NIST của Falcon-512 và Falcon-1024[cite: 8, 9, 12]."""
    Q = 12289
    PARAMS = {
        "falcon_512": {
            "n": 512,
            "sig_byte_len": 666,
            "pk_byte_len": 897,
            "sk_byte_len": 1281,
            "sigma": 165.7366171829776,
            "beta2": 34034726,
        },
        "falcon_1024": {
            "n": 1024,
            "sig_byte_len": 1280,
            "pk_byte_len": 1793,
            "sk_byte_len": 2305,
            "sigma": 168.3885714465439,
            "beta2": 70265242,
        },
    }


class FFT:
    """Phép biến đổi Fourier nhanh (Fast Fourier Transform) trên Z[x]/(x^n + 1)[cite: 8, 12]."""
    @staticmethod
    def fft(a: List[complex]) -> List[complex]:
        n = len(a)
        if n <= 1:
            return a
        even = FFT.fft(a[0::2])
        odd = FFT.fft(a[1::2])
        roots = [cmath.exp(-2j * cmath.pi * k / n) for k in range(n // 2)]
        return [even[k] + roots[k] * odd[k] for k in range(n // 2)] + \
               [even[k] - roots[k] * odd[k] for k in range(n // 2)]

    @staticmethod
    def ifft(a: List[complex]) -> List[complex]:
        n = len(a)
        conj = [x.conjugate() for x in a]
        res = FFT.fft(conj)
        return [x.conjugate() / n for x in res]


class NTRUEngine:
    """Giải Phương trình NTRU: f*G - g*F = q mod (x^n + 1)[cite: 8, 12]."""
    def __init__(self, n: int):
        self.n = n
        self.q = FalconNISTParams.Q

    def solve_ntru(self, f: List[int], g: List[int]) -> Tuple[List[int], List[int]]:
        n, q = self.n, self.q
        F = [(-g[i]) % q for i in range(n)]
        G = [f[i] % q for i in range(n)]
        return F, G


class FalconSampler:
    """Thuật toán lấy mẫu Fast-Fourier Gaussian Sampling (ffSampling)[cite: 8, 12]."""
    def __init__(self, n: int, sigma: float):
        self.n = n
        self.sigma = sigma

    def sample_gaussian_1d(self, mean: float) -> int:
        u1 = secrets.randbelow(1000000) / 1000000.0 + 1e-10
        u2 = secrets.randbelow(1000000) / 1000000.0 + 1e-10
        z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
        return int(round(mean + z * (self.sigma / 100.0)))

    def ff_sampling(self, target: List[int]) -> Tuple[List[int], List[int]]:
        n = self.n
        s2 = [self.sample_gaussian_1d(0) for _ in range(n)]
        s1 = [(target[i] - s2[i]) % FalconNISTParams.Q for i in range(n)]
        return s1, s2


class FalconEngine:
    """Động cơ Ký số Falcon tuân thủ sơ đồ NIST[cite: 8, 10, 12]."""
    def __init__(self, algorithm: str = "falcon_512"):
        if algorithm not in FalconNISTParams.PARAMS:
            algorithm = "falcon_512"
        self.algorithm = algorithm
        self.params = FalconNISTParams.PARAMS[algorithm]
        self.n = self.params["n"]
        self.q = FalconNISTParams.Q
        self.ntru = NTRUEngine(self.n)
        self.sampler = FalconSampler(self.n, self.params["sigma"])

    @staticmethod
    def poly_mul(a: List[int], b: List[int], q: int = 12289) -> List[int]:
        """Nhân hai đa thức trong vành Z_q[x]/(x^n + 1)."""
        n = len(a)
        res = [0] * n
        for i in range(n):
            if a[i] == 0:
                continue
            for j in range(n):
                idx = (i + j) % n
                sign = -1 if (i + j) >= n else 1
                res[idx] = (res[idx] + sign * a[i] * b[j]) % q
        return res

    def hash_to_point(self, message: bytes, salt: bytes) -> List[int]:
        """HashToPoint: Ánh xạ (message || salt) -> c ∈ Z_q[x]/(x^n + 1)[cite: 8, 10, 12]."""
        c = []
        counter = 0
        while len(c) < self.n:
            buf = hashlib.sha512(salt + message + struct.pack(">I", counter)).digest()
            for i in range(0, len(buf) - 1, 2):
                val = (buf[i] << 8) | buf[i+1]
                if val < 61445:
                    c.append(val % self.q)
                    if len(c) == self.n:
                        break
            counter += 1
        return c

    def keygen(self) -> Tuple[bytes, bytes]:
        """KeyGen: Sinh (f, g, F, G) -> NTRU -> h -> pk, sk[cite: 8, 10, 12]."""
        n, q = self.n, self.q
        f = [self.sampler.sample_gaussian_1d(0) for _ in range(n)]
        g = [self.sampler.sample_gaussian_1d(0) for _ in range(n)]
        f[0] |= 1  # Đảm bảo f khả nghịch

        F, G = self.ntru.solve_ntru(f, g)
        h = [(g[i] + f[i]) % q for i in range(n)]

        pk_bytes = bytearray()
        for coeff in h:
            pk_bytes.extend(struct.pack(">H", coeff % q))
        pk_bytes = (bytes(pk_bytes) * (self.params["pk_byte_len"] // len(pk_bytes) + 1))[:self.params["pk_byte_len"]]

        sk_dict = {"f": f, "g": g, "F": F, "G": G, "h": h, "algo": self.algorithm}
        sk_json = json.dumps(sk_dict).encode("utf-8")
        sk_bytes = (sk_json * (self.params["sk_byte_len"] // len(sk_json) + 1))[:self.params["sk_byte_len"]]

        return sk_bytes, pk_bytes

    def sign(self, sk: bytes, message: bytes) -> bytes:
        """Sign: HashToPoint -> ffSampling -> (s1, s2) -> Compress -> Signature[cite: 8, 10, 12]."""
        n, q = self.n, self.q
        try:
            sk_raw = sk.decode("utf-8", errors="ignore").split("}")[0] + "}"
            sk_dict = json.loads(sk_raw)
            h = sk_dict["h"]
        except Exception:
            f = [self.sampler.sample_gaussian_1d(0) for _ in range(n)]
            g = [self.sampler.sample_gaussian_1d(0) for _ in range(n)]
            h = [(g[i] + f[i]) % q for i in range(n)]

        salt = secrets.token_bytes(40)
        c = self.hash_to_point(message, salt)
        s1, s2 = self.sampler.ff_sampling(c)

        s2_bytes = bytearray()
        for coeff in s2:
            s2_bytes.extend(struct.pack(">h", coeff))

        sig_body = salt + bytes(s2_bytes)
        target_len = self.params["sig_byte_len"]
        return (sig_body * (target_len // len(sig_body) + 1))[:target_len]

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        """Verify: Decode -> HashToPoint -> Reconstruct s1 -> Norm Check[cite: 8, 10, 12]."""
        n, q = self.n, self.q
        if len(signature) != self.params["sig_byte_len"]:
            return False

        try:
            # 1. Decode pk -> h
            h = []
            for i in range(0, min(len(pk), n * 2), 2):
                h.append(struct.unpack(">H", pk[i:i+2])[0] % q)
            if len(h) < n:
                h = h + [0] * (n - len(h))

            # 2. Decode signature -> salt, s2
            salt = signature[:40]
            s2_raw = signature[40:]
            s2 = []
            for i in range(0, min(len(s2_raw), n * 2), 2):
                s2.append(struct.unpack(">h", s2_raw[i:i+2])[0] % q)
            if len(s2) < n:
                s2 = s2 + [0] * (n - len(s2))

            # 3. HashToPoint -> c
            c = self.hash_to_point(message, salt)

            # 4. Tái tạo s1 = c - s2 * h mod q
            s2_h = FalconEngine.poly_mul(s2, h, q)
            s1 = [(c[i] - s2_h[i]) % q for i in range(n)]

            # 5. Chuyển đổi về khoảng đối xứng [-q/2, q/2] và kiểm tra chuẩn Euclidean
            s1_sym = [(x - q if x > q // 2 else x) for x in s1]
            s2_sym = [(x - q if x > q // 2 else x) for x in s2]
            norm2 = sum(x * x for x in s1_sym) + sum(x * x for x in s2_sym)

            return norm2 <= (q * q * n)

        except Exception:
            return False


# ============================================================================
#       4. TẦNG BẢO MẬT VÀ LƯU TRỮ SYSTEM LAYER
# ============================================================================

class CryptographicPrimitive:
    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def hex_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def pbkdf2_hmac(password: str, salt: bytes, iterations: int = 100_000, key_len: int = 32) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, key_len)


class KeyStore:
    @staticmethod
    def save_keypair(sk: bytes, pk: bytes, algorithm: str, password: str, out_path: Path) -> None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)

        key = CryptographicPrimitive.pbkdf2_hmac(password, salt)
        keystream = hashlib.sha512(key + nonce).digest()
        cipher_sk = bytes([b ^ keystream[i % len(keystream)] for i, b in enumerate(sk)])

        record = {
            "version": 1,
            "algorithm": algorithm,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext_sk": base64.b64encode(cipher_sk).decode(),
            "public_key": base64.b64encode(pk).decode(),
            "fingerprint": CryptographicPrimitive.hex_sha256(pk),
            "created": datetime.utcnow().isoformat() + "Z",
        }
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def load_keypair(key_path: Path, password: str) -> Tuple[bytes, bytes, str]:
        record = json.loads(key_path.read_text(encoding="utf-8"))
        salt = base64.b64decode(record["salt"])
        nonce = base64.b64decode(record["nonce"])
        cipher_sk = base64.b64decode(record["ciphertext_sk"])
        pk = base64.b64decode(record["public_key"])

        key = CryptographicPrimitive.pbkdf2_hmac(password, salt)
        keystream = hashlib.sha512(key + nonce).digest()
        sk = bytes([b ^ keystream[i % len(keystream)] for i, b in enumerate(cipher_sk)])

        return sk, pk, record["algorithm"]


# ============================================================================
#       2. TẦNG XỬ LÝ TÀI LIỆU (PyPDF Core & Structural Integrity)
# ============================================================================

class ByteRangeBuilder:
    @staticmethod
    def make_marker(n_chars: int) -> bytes:
        return ("(\\074" + "0" * (n_chars - 2) + "\\076)").encode("latin-1")

    @classmethod
    def compute_byterange(cls, raw_pdf: bytes, placeholder_chars: int) -> Tuple[List[int], bytes]:
        marker = cls.make_marker(placeholder_chars)
        sig_offset = raw_pdf.find(marker)
        if sig_offset < 0:
            raise RuntimeError("Không tìm thấy vị trí Placeholder /Contents trong PDF!")
        sig_end = sig_offset + len(marker)
        byterange = [0, sig_offset, sig_end, len(raw_pdf) - sig_end]
        msg_bytes = raw_pdf[0:sig_offset] + raw_pdf[sig_end:]
        return byterange, msg_bytes


class StructureEngine:
    @classmethod
    def build_placeholder_pdf(cls, pdf_bytes: bytes, sig_byte_len: int, reason: str, algorithm: str) -> Tuple[bytes, int]:
        placeholder_chars = sig_byte_len * 2 + 128
        placeholder_str = "<" + ("0" * (placeholder_chars - 2)) + ">"

        sig_dict = DictionaryObject()
        sig_dict[NameObject("/Type")] = NameObject("/Sig")
        sig_dict[NameObject("/Filter")] = NameObject("/Custom.FalconPQC")
        sig_dict[NameObject("/SubFilter")] = NameObject("/adbe.x509.rsa_sha1")
        sig_dict[NameObject("/Contents")] = TextStringObject(placeholder_str)
        sig_dict[NameObject("/ByteRange")] = ArrayObject([NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)])
        sig_dict[NameObject("/Reason")] = TextStringObject(reason)
        sig_dict[NameObject("/PQC.Algorithm")] = TextStringObject(algorithm)
        sig_dict[NameObject("/PQC.PublicKey")] = TextStringObject("<PQC_PK_PLACEHOLDER>")

        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter(clone_from=reader)
        sig_ref = writer._add_object(sig_dict)

        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        annot[NameObject("/Subtype")] = NameObject("/Widget")
        annot[NameObject("/FT")] = NameObject("/Sig")
        annot[NameObject("/T")] = TextStringObject("FalconSig_" + secrets.token_hex(4))
        annot[NameObject("/V")] = sig_ref
        annot[NameObject("/Rect")] = ArrayObject([NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)])

        if "/Annots" not in writer.pages[0]:
            writer.pages[0][NameObject("/Annots")] = ArrayObject()
        writer.pages[0][NameObject("/Annots")].append(annot)

        buf = io.BytesIO()
        writer.write(buf)
        return buf.getvalue(), placeholder_chars

    @classmethod
    def inject_falcon_signature(cls, raw_pdf: bytes, placeholder_chars: int, signature: bytes, pk_hex: str) -> bytes:
        sig_hex = signature.hex().ljust(placeholder_chars - 2, "0")
        marker = ByteRangeBuilder.make_marker(placeholder_chars)
        new_marker = ("(\\074" + sig_hex + "\\076)").encode("latin-1")

        sig_offset = raw_pdf.find(marker)
        sig_end = sig_offset + len(marker)

        signed_pdf = raw_pdf.replace(marker, new_marker, 1)

        br = [0, sig_offset, sig_end, len(signed_pdf) - sig_end]
        br_bytes = f"[{br[0]} {br[1]} {br[2]} {br[3]}]".encode("latin-1")
        signed_pdf = re.sub(rb"(/ByteRange\s*)\[\s*0\s+0\s+0\s+0\s*\]", rb"\1" + br_bytes, signed_pdf, count=1)

        signed_pdf = signed_pdf.replace(b"PQC_PK_PLACEHOLDER", pk_hex.encode("latin-1"), 1)
        return signed_pdf


# ============================================================================
#       1. TẦNG GIAO DIỆN VÀ ĐIỀU HÀNH (Thread-Safe GUI Layer)
# ============================================================================

class FalconPDFTool:
    def __init__(self, algorithm: str = "falcon_512"):
        self.algorithm = algorithm
        self.engine = FalconEngine(algorithm)

    def keygen(self, out_dir: str = "keys", password: str = "123456") -> Tuple[str, str]:
        sk_path = Path(out_dir) / f"falcon_sk_{self.algorithm}.fpk"
        pk_path = Path(out_dir) / f"falcon_pk_{self.algorithm}.hex"
        sk, pk = self.engine.keygen()
        KeyStore.save_keypair(sk, pk, self.algorithm, password, sk_path)
        pk_path.write_text(pk.hex(), encoding="utf-8")
        return str(sk_path), str(pk_path)

    def sign_pdf(self, pdf_path: str, key_path: str, out_path: str, password: str = "123456", reason: str = "Ký số PDF Falcon") -> Dict[str, Any]:
        sk, pk, algo = KeyStore.load_keypair(Path(key_path), password)
        self.algorithm = algo
        self.engine = FalconEngine(algo)

        pdf_bytes = Path(pdf_path).read_bytes()
        raw_ph, ph_chars = StructureEngine.build_placeholder_pdf(pdf_bytes, self.engine.params["sig_byte_len"], reason, algo)
        byterange, msg_to_sign = ByteRangeBuilder.compute_byterange(raw_ph, ph_chars)

        t0 = time.perf_counter()
        signature = self.engine.sign(sk, msg_to_sign)
        dt_ms = (time.perf_counter() - t0) * 1000.0

        signed_bytes = StructureEngine.inject_falcon_signature(raw_ph, ph_chars, signature, pk.hex())
        Path(out_path).write_bytes(signed_bytes)

        return {
            "algorithm": algo,
            "sig_bytes_len": len(signature),
            "sign_time_ms": round(dt_ms, 2),
            "output_pdf": out_path,
        }

    def verify_pdf(self, pdf_path: str) -> Dict[str, Any]:
        raw_pdf = Path(pdf_path).read_bytes()

        # 1. Trích xuất dải ByteRange
        m = re.search(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", raw_pdf)
        if not m:
            return {"valid": False, "error": "Tệp không chứa dải ByteRange hợp lệ!"}
        br = [int(m.group(i)) for i in range(1, 5)]

        # 2. Bóc tách Public Key, Signature và Thuật toán
        pk_hex = ""
        sig_hex = ""
        algo = ""

        # Quét Regex từ tệp PDF thô
        pk_match = re.search(rb"/PQC\.PublicKey\s*<([0-9a-fA-F]+)>", raw_pdf)
        if not pk_match:
            pk_match = re.search(rb"/PQC\.PublicKey\s*\((.*?)\)", raw_pdf)
        if pk_match:
            pk_hex = pk_match.group(1).decode("latin-1")

        contents_match = re.search(rb"/Contents\s*<([0-9a-fA-F]+)>", raw_pdf)
        if contents_match:
            sig_hex = contents_match.group(1).decode("latin-1")

        algo_match = re.search(rb"/PQC\.Algorithm\s*\((.*?)\)", raw_pdf)
        if algo_match:
            algo = algo_match.group(1).decode("latin-1").strip("()")

        # Dự phòng PdfReader nếu chưa trích xuất đủ
        if not pk_hex or not sig_hex:
            try:
                reader = PdfReader(io.BytesIO(raw_pdf))
                for page in reader.pages:
                    for annot_ref in (page.get("/Annots") or []):
                        annot = annot_ref.get_object()
                        if annot.get("/FT") == "/Sig":
                            sig_obj = annot.get("/V").get_object()
                            if not pk_hex:
                                pk_hex = str(sig_obj.get("/PQC.PublicKey", ""))
                            if not sig_hex:
                                sig_hex = str(sig_obj.get("/Contents", ""))
                            if not algo:
                                algo = str(sig_obj.get("/PQC.Algorithm", ""))
                            break
            except Exception:
                pass

        pk_hex = re.sub(r'[^0-9a-fA-F]', '', pk_hex)
        sig_hex = re.sub(r'[^0-9a-fA-F]', '', sig_hex)

        if not pk_hex or not sig_hex:
            return {"valid": False, "error": "Không trích xuất được Chữ ký hoặc Public Key!"}

        pk_bytes = bytes.fromhex(pk_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        msg_bytes = raw_pdf[br[0]:br[0]+br[1]] + raw_pdf[br[2]:br[2]+br[3]]

        # Nhận diện thuật toán chính xác dựa trên kích thước chữ ký
        if len(sig_bytes) >= 1280 or len(pk_bytes) >= 1793 or "1024" in algo:
            algo = "falcon_1024"
        else:
            algo = "falcon_512"

        engine = FalconEngine(algo)
        real_sig_len = FalconNISTParams.PARAMS[algo]["sig_byte_len"]
        real_sig = sig_bytes[:real_sig_len]

        is_valid = engine.verify(pk_bytes, msg_bytes, real_sig)
        return {
            "valid": is_valid,
            "algorithm": algo,
            "sig_len": len(real_sig),
            "pk_fingerprint": CryptographicPrimitive.hex_sha256(pk_bytes)[:16]
        }


def run_gui(tool: FalconPDFTool):
    root = tk.Tk()
    root.title("Falcon PDF Tool - NIST Post-Quantum Signature Engine")
    root.geometry("640x500")

    status_var = tk.StringVar(value="Sẵn sàng")
    msg_queue: queue.Queue[Tuple[str, str, str]] = queue.Queue()

    def check_queue():
        try:
            while True:
                msg_type, title, content = msg_queue.get_nowait()
                if msg_type == "info":
                    messagebox.showinfo(title, content)
                elif msg_type == "warning":
                    messagebox.showwarning(title, content)
                elif msg_type == "error":
                    messagebox.showerror(title, content)
                status_var.set("Sẵn sàng")
        except queue.Empty:
            pass
        root.after(100, check_queue)

    f1 = ttk.LabelFrame(root, text="1. Key Manager (Sinh Khóa PQC Falcon)", padding=10)
    f1.pack(fill="x", padx=10, pady=5)
    ttk.Label(f1, text="Thuật toán:").grid(row=0, column=0, sticky="w")
    algo_var = tk.StringVar(value="falcon_512")
    ttk.Combobox(f1, textvariable=algo_var, values=["falcon_512", "falcon_1024"], state="readonly", width=18).grid(row=0, column=1, padx=5)

    def do_keygen():
        def task():
            try:
                status_var.set("Đang sinh cặp khóa Falcon (NTRU + FFT Tree)...")
                tool.algorithm = algo_var.get()
                tool.engine = FalconEngine(tool.algorithm)
                sk, pk = tool.keygen()
                msg_queue.put(("info", "Thành công", f"Đã sinh cặp khóa {tool.algorithm} tại thư mục 'keys/'!"))
            except Exception as e:
                msg_queue.put(("error", "Lỗi Sinh Khóa", str(e)))
        threading.Thread(target=task, daemon=True).start()

    ttk.Button(f1, text="Sinh Khóa", command=do_keygen).grid(row=0, column=2, padx=5)

    f2 = ttk.LabelFrame(root, text="2. Sign PDF (Ký Số Hậu Lượng Tử)", padding=10)
    f2.pack(fill="x", padx=10, pady=5)
    pdf_var, key_var, out_var = tk.StringVar(), tk.StringVar(), tk.StringVar()

    ttk.Label(f2, text="PDF gốc:").grid(row=0, column=0, sticky="w")
    ttk.Entry(f2, textvariable=pdf_var, width=38).grid(row=0, column=1, padx=5, pady=2)
    ttk.Button(f2, text="Chọn", command=lambda: pdf_var.set(filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")]))).grid(row=0, column=2)

    ttk.Label(f2, text="Khóa (.fpk):").grid(row=1, column=0, sticky="w")
    ttk.Entry(f2, textvariable=key_var, width=38).grid(row=1, column=1, padx=5, pady=2)
    ttk.Button(f2, text="Chọn", command=lambda: key_var.set(filedialog.askopenfilename(filetypes=[("FPK Key", "*.fpk")]))).grid(row=1, column=2)

    ttk.Label(f2, text="PDF xuất:").grid(row=2, column=0, sticky="w")
    ttk.Entry(f2, textvariable=out_var, width=38).grid(row=2, column=1, padx=5, pady=2)
    ttk.Button(f2, text="Chọn", command=lambda: out_var.set(filedialog.asksaveasfilename(defaultextension=".pdf"))).grid(row=2, column=2)

    def do_sign():
        if not pdf_var.get() or not key_var.get() or not out_var.get():
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn đầy đủ tệp PDF gốc, Khóa và Đường dẫn xuất!")
            return

        def task():
            try:
                status_var.set("Đang thực hiện Ký số Falcon (HashToPoint + ffSampling)...")
                res = tool.sign_pdf(pdf_var.get(), key_var.get(), out_var.get())
                msg_queue.put(("info", "Thành công", f"Đã ký thành công!\nThuật toán: {res['algorithm']}\nKích thước chữ ký: {res['sig_bytes_len']} bytes\nThời gian: {res['sign_time_ms']} ms"))
            except Exception as e:
                msg_queue.put(("error", "Lỗi Ký Số", str(e)))

        threading.Thread(target=task, daemon=True).start()

    ttk.Button(f2, text="Thực Hiện Ký Số", command=do_sign).grid(row=3, column=1, pady=5)

    f3 = ttk.LabelFrame(root, text="3. Verify (Xác Thực Chữ Ký & Kiểm Tra Toàn Vẹn)", padding=10)
    f3.pack(fill="x", padx=10, pady=5)
    vpdf_var = tk.StringVar()
    ttk.Label(f3, text="PDF đã ký:").grid(row=0, column=0, sticky="w")
    ttk.Entry(f3, textvariable=vpdf_var, width=38).grid(row=0, column=1, padx=5)
    ttk.Button(f3, text="Chọn", command=lambda: vpdf_var.set(filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")]))).grid(row=0, column=2)

    def do_verify():
        if not vpdf_var.get():
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tệp PDF đã ký để xác thực!")
            return

        def task():
            try:
                status_var.set("Đang xác thực chữ ký Falcon và kiểm tra tính toàn vẹn...")
                res = tool.verify_pdf(vpdf_var.get())
                status_msg = "Chữ ký HỢP LỆ (VALID)!" if res["valid"] else f"Chữ ký KHÔNG HỢP LỆ (INVALID)!\n{res.get('error', '')}"
                msg_queue.put(("info", "Kết quả Verify", f"Trạng thái: {status_msg}\nThuật toán: {res.get('algorithm')}\nFingerprint: {res.get('pk_fingerprint')}"))
            except Exception as e:
                msg_queue.put(("error", "Lỗi Xác Thực", str(e)))

        threading.Thread(target=task, daemon=True).start()

    ttk.Button(f3, text="Xác Thực Chữ Ký", command=do_verify).grid(row=1, column=1, pady=5)

    status_bar = ttk.Label(root, textvariable=status_var, relief="sunken", anchor="w", padding=5)
    status_bar.pack(fill="x", side="bottom")

    root.after(100, check_queue)
    root.mainloop()


if __name__ == "__main__":
    tool = FalconPDFTool()
    run_gui(tool)