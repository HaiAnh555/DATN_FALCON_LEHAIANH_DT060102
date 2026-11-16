#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
ĐỒ ÁN TỐT NGHIỆP: NGHIÊN CỨU TÍCH HỢP CÔNG CỤ TRÍCH XUẤT VÀ KÝ TÀI LIỆU PDF
                 BẢO MẬT SỬ DỤNG KÝ SỐ HẬU LƯỢNG TỬ FALCON
Sinh viên thực hiện: Lê Hải Anh - DT060102
Khóa: 19 - Khoa Điện tử - Vi mạch, Học viện Kỹ thuật Mật mã
Liên hệ: lehaianh150303@gmail.com - Hà Đông, Hà Nội
================================================================================

BẢN ĐỒ ÁNH XẠ "ĐỒ ÁN  <->  MÃ NGUỒN"
(Kiến trúc 4 tầng - Mục 2.3.1, Hình 2.3)

  Tầng 1 - Giao diện & Điều hành (GUI/CLI/API)
      run_gui() ................................ Mục 2.3.1 (Tầng 1), Mục 3.3
      server.py (Web đa người dùng) ............ Mở rộng Tầng 1 qua HTTP

  Tầng 2 - Xử lý Tài liệu (PyPDF Core Module)
      StructureEngine.build_placeholder_pdf .... Mục 1.3, 2.2.2.a Bước 1, 3.2.2 Giai đoạn 1
      ByteRangeBuilder.compute_byterange ....... Mục 1.3 (/ByteRange), 2.2.2.a Bước 2, 3.2.2 Giai đoạn 2
      StructureEngineInject.inject_falcon_signature  Mục 2.2.2.a Bước 6, 2.3.2 (Signature Injection)
      FalconPDFTool.extract_text_and_properties  Mục 1.4.1.b, 2.1.2

  Tầng 3 - Ký số Hậu lượng tử (Falcon Engine Module)  ->  tệp falcon_core.py
      FalconNISTParams ......................... Mục 1.2.1, 3.2.1 (Quản lý tham số chuẩn)
      FFT (fft/ifft/split_fft/merge_fft) ....... Mục 1.2.2.b, 3.2.1 (cây FFT, nhân đa thức O(n log n))
      NTT (mul_zq/div_zq) ...................... Mục 1.2.1, 1.2.3.a (số học nguyên mod q)
      SamplerZ ................................. Mục 1.2.2.b (Gaussian 1 chiều tại lá), 1.2.3.b
      NTRUEngine.ntru_gen / ntru_solve ......... Mục 1.2.1 (f·G − g·F = q), 1.2.4.a, 2.2.1.a
      FalconSampler.ffldl / ff_sampling ........ Mục 1.2.2.b (cây LDL + ffSampling), 3.2.1
      FalconEncoding (pk, sk, Compress) ........ Mục 2.2.1.b, 1.2.4.b
      FalconEngine.hash_to_point ............... Mục 1.2.2.a (HashToPoint), 2.2.2.a Bước 5
      FalconEngine.keygen ...................... Mục 1.2.4.a, 2.2.1
      FalconEngine.sign ........................ Mục 1.2.4.b, 2.2.2.a Bước 5
      FalconEngine.verify ...................... Mục 1.2.4.c, 2.2.2.b Bước 5-6

  Tầng 4 - Bảo mật & Lưu trữ (System Layer)
      CryptographicPrimitive ................... Mục 2.3.1 (Tầng 4), 3.1.2 (hashlib)
      KeyStore (PBKDF2 + AES-256-GCM) .......... Mục 2.2.1.b, 3.3 (Quy trình sinh khóa)
      PasswordManager .......................... Mục 3.3

  Quy trình tổng (điều phối các tầng)
      FalconPDFTool.keygen ..................... Mục 3.3 "Quy trình sinh khóa"
      FalconPDFTool.sign_pdf ................... Mục 2.2.2.a (6 bước), 3.2.2, 3.3 "Quy trình ký số"
      FalconPDFTool.verify_pdf ................. Mục 2.2.2.b (6 bước), 3.3 "Quy trình xác thực"

GHI CHÚ CÀI ĐẶT:
  Lõi Falcon (falcon_core.py) là cài đặt đầy đủ theo đặc tả Falcon / FIPS 206:
  NTRUGen + NTRUSolve, cây LDL, ffSampling, SamplerZ, HashToPoint (SHAKE-256),
  Compress, kiểm tra β². Đã đối chiếu khớp 100/100 vector kiểm thử chính thức
  (NIST KAT) cho mỗi mức Falcon-512 và Falcon-1024.
================================================================================
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import secrets
import struct
import sys
import threading
import time
import queue
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Tkinter chỉ cần cho giao diện desktop; bản Android (Kivy) không có tkinter
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    tk = ttk = filedialog = messagebox = None

# Import PyPDF Core  (Mục 1.4 - thư viện PyPDF thuần Python, Mục 3.1.2 - pypdf)
try:
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        ArrayObject, DictionaryObject, NameObject, NumberObject, TextStringObject
    )
    PYPDF_OK = True
except ImportError:
    PYPDF_OK = False

# AES-256-GCM bảo vệ tệp khóa bí mật (Mục 2.2.1.b: "PBKDF2 kết hợp AES-256")
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Tầng 3 - lõi Falcon (cài đặt đầy đủ, xem falcon_core.py)
from falcon_core import (  # noqa: F401  (tái xuất để server.py và mã cũ dùng chung)
    FFT, NTT, FalconEncoding, FalconEngine, FalconNISTParams, FalconSampler,
    NTRUEngine, SamplerZ,
)

AUTHOR_EMAIL = "lehaianh150303@gmail.com"
AUTHOR_ADDRESS = "Hà Đông - Hà Nội"
AUTHOR_PHONE = "0329242296"
AUTHOR_SUPERVISOR = "TS. Lục Như Quỳnh"
APP_VERSION = "v3.1.0"

def _app_dir() -> Path:
    """Thư mục chứa dữ liệu thật (keys/, server_data/).

    - Chạy bằng Python: thư mục chứa tệp .py.
    - Chạy bản .exe (PyInstaller): __file__ nằm trong thư mục giải nén tạm _MEIxxxx
      (bị xóa khi thoát) -> phải dùng thư mục chứa tệp .exe. Nếu .exe nằm trong
      dist/ của dự án thì dùng thư mục dự án (cha của dist/) để thấy dữ liệu cũ.
    """
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        has_data = lambda d: (d / "keys").is_dir() or (d / "server_data").is_dir()
        if not has_data(exe_dir) and exe_dir.name.lower() == "dist" and has_data(exe_dir.parent):
            return exe_dir.parent
        return exe_dir
    return Path(__file__).resolve().parent


APP_DIR = _app_dir()
# Thư mục lưu khóa: keys/<người dùng>/public/keyN.hex và keys/<người dùng>/private/privateN.fpk
KEYS_ROOT = APP_DIR / "keys"
# Danh sách tài khoản - dùng chung với server web (server.py)
USERS_FILE = APP_DIR / "server_data" / "users.json"
PUBLIC_DIR_NAME = "public"
PRIVATE_DIR_NAME = "private"

# Phần đuôi ghi vào vùng đệm /Contents (sau chữ ký) để lưu thời gian ký.
# Vùng /Contents bị loại khỏi /ByteRange (Mục 1.3), nên phần đuôi này KHÔNG làm
# thay đổi giá trị băm - chỉ mang tính thông tin hiển thị "Ký trong ... ms".
SIGN_TIME_MARKER = b"FTMS"


# ==============================================================================
#   TẦNG 3. KHỐI KÝ SỐ HẬU LƯỢNG TỬ FALCON  (Mục 1.2, 2.2, 3.2.1)
#   Toàn bộ thuật toán nằm trong falcon_core.py (đã import ở đầu tệp):
#     FalconNISTParams, FFT, NTT, SamplerZ, NTRUEngine, FalconSampler,
#     FalconEncoding, FalconEngine (hash_to_point / keygen / sign / verify).
# ==============================================================================


# ==============================================================================
#   TẦNG 4. BẢO MẬT & LƯU TRỮ HỆ THỐNG  (Mục 2.3.1 Tầng 4, 2.2.1.b)
# ==============================================================================

class CryptographicPrimitive:
    """Nguyên thủy mật mã bổ trợ: SHA-256, PBKDF2 (Mục 2.3.1 Tầng 4, 3.1.2 hashlib)."""
    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def hex_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def pbkdf2_hmac(password: str, salt: bytes, iterations: int = 100_000, key_len: int = 32) -> bytes:
        # PBKDF2-HMAC-SHA256, 100.000 vòng lặp -> khóa 256 bit bảo vệ tệp .fpk
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, key_len)


class PasswordManager:
    """Quản lý mật khẩu: tạo, xác nhận, băm xác thực (Mục 3.3 - hộp thoại PasswordManager)."""
    AUTH_PEPPER = b"FALCON_PDF_AUTH_v1"

    @staticmethod
    def hash_password(password: str) -> str:
        """Băm mật khẩu để lưu vào metadata PDF (/FalconPQC_AuthHash)."""
        return hashlib.sha256(password.encode("utf-8") + PasswordManager.AUTH_PEPPER).hexdigest()

    @staticmethod
    def verify_password_hash(password: str, stored_hash: str) -> bool:
        if not password or not stored_hash or stored_hash in ("N/A", "None", ""):
            return False
        return PasswordManager.hash_password(password) == stored_hash.strip().lower()

    @staticmethod
    def ask_password(parent, title: str = "Nhập mật khẩu", confirm: bool = False) -> Optional[str]:
        """Hộp thoại nhập mật khẩu. confirm=True yêu cầu nhập lại lần 2."""
        dlg = tk.Toplevel(parent)
        dlg.title(title)
        dlg.configure(bg=Theme.CARD)
        dlg.resizable(False, False)
        dlg.transient(parent)
        dlg.grab_set()

        result: Dict[str, Optional[str]] = {"value": None}
        body = ttk.Frame(dlg, style="Card.TFrame", padding=18)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text=title, style="DialogTitle.TLabel").pack(anchor="w", pady=(0, 10))
        ttk.Label(body, text="Mật khẩu:" if not confirm else "Tạo mật khẩu mới:", style="Card.TLabel").pack(anchor="w")
        e1 = ttk.Entry(body, show="•", width=34, font=Theme.INPUT)
        e1.pack(fill="x", pady=(2, 8))
        e1.focus_set()

        e2 = None
        if confirm:
            ttk.Label(body, text="Xác nhận mật khẩu:", style="Card.TLabel").pack(anchor="w")
            e2 = ttk.Entry(body, show="•", width=34, font=Theme.INPUT)
            e2.pack(fill="x", pady=(2, 8))

        err_var = tk.StringVar(value="")
        ttk.Label(body, textvariable=err_var, style="Error.TLabel").pack(anchor="w")

        def on_ok():
            p1 = e1.get()
            if not p1:
                err_var.set("Mật khẩu không được để trống!")
                return
            if len(p1) < 6:
                err_var.set("Mật khẩu phải có ít nhất 6 ký tự!")
                return
            if confirm:
                p2 = e2.get() if e2 else ""
                if p1 != p2:
                    err_var.set("Hai lần nhập mật khẩu không khớp!")
                    return
            result["value"] = p1
            dlg.destroy()

        def on_cancel():
            result["value"] = None
            dlg.destroy()

        btn_frame = ttk.Frame(body, style="Card.TFrame")
        btn_frame.pack(fill="x", pady=(10, 0))
        ttk.Button(btn_frame, text="Hủy", style="Ghost.TButton", command=on_cancel).pack(side="right", padx=(6, 0))
        ttk.Button(btn_frame, text="Xác nhận", style="Accent.TButton", command=on_ok).pack(side="right")

        dlg.bind("<Return>", lambda e: on_ok())
        dlg.bind("<Escape>", lambda e: on_cancel())
        _center_on_parent(dlg, parent)
        parent.wait_window(dlg)
        return result["value"]


class KeyStore:
    """Lưu trữ khóa an toàn (Mục 2.2.1.b, Mục 3.3 "Quy trình sinh khóa").

    Bố cục thư mục (mỗi người dùng một nhánh, khóa công khai / bí mật tách riêng):
        keys/<user>/public/key1.hex,     key2.hex,     ...
        keys/<user>/private/private1.fpk, private2.fpk, ...
    Cặp khóa cùng số thứ tự N (keyN <-> privateN) là một cặp.

    Tệp .fpk (định dạng version 3) - "PBKDF2 kết hợp AES-256" (Mục 2.2.1.b):
        K  = PBKDF2-HMAC-SHA256(mật khẩu, salt 16 byte, 100.000 vòng) -> 256 bit
        ct = AES-256-GCM(K, nonce 12 byte, sk, AAD = "FalconPDFTool|v3|<thuật toán>")
    sk là khóa bí mật Falcon dạng chuẩn 1281 / 2305 byte (f, g, F).
    Thẻ xác thực GCM 16 byte vừa bảo vệ toàn vẹn tệp khóa, vừa dùng để phát
    hiện sai mật khẩu (giải mã thất bại -> "Mật khẩu không đúng!").
    Tệp version < 3 do bản mô phỏng cũ tạo ra -> không dùng được, phải sinh lại.

    Khóa sinh từ v3.1 không còn hỏi mật khẩu: "mật khẩu" ở công thức trên là
    chuỗi nội bộ INTERNAL_PASSPHRASE và bản ghi có "protected": false. Khóa cũ
    có mật khẩu người dùng ("protected" vắng mặt / true) vẫn dùng được.
    """
    FORMAT_VERSION = 3
    INTERNAL_PASSPHRASE = "FalconPDFTool|internal-key|v3"

    @staticmethod
    def is_protected(record: Dict[str, Any]) -> bool:
        """True nếu khóa bí mật được mã hóa bằng mật khẩu do người dùng đặt."""
        return record.get("protected", True)

    @staticmethod
    def key_is_protected(key_path: Union[str, Path]) -> bool:
        try:
            return KeyStore.is_protected(json.loads(Path(key_path).read_text(encoding="utf-8")))
        except Exception:
            return False

    @staticmethod
    def _aad(algorithm: str) -> bytes:
        return f"FalconPDFTool|v3|{algorithm}".encode("utf-8")

    @staticmethod
    def user_dirs(owner: str, root: Path = KEYS_ROOT) -> Tuple[Path, Path]:
        base = Path(root) / safe_name(owner)
        return base / PUBLIC_DIR_NAME, base / PRIVATE_DIR_NAME

    @staticmethod
    def next_index(owner: str, root: Path = KEYS_ROOT) -> int:
        """Số thứ tự kế tiếp N cho cặp keyN / privateN."""
        pub_dir, priv_dir = KeyStore.user_dirs(owner, root)
        used = set()
        for d, pattern in ((pub_dir, r"key(\d+)\.hex$"), (priv_dir, r"private(\d+)\.fpk$")):
            if d.is_dir():
                for p in d.iterdir():
                    m = re.match(pattern, p.name)
                    if m:
                        used.add(int(m.group(1)))
        return (max(used) + 1) if used else 1

    @staticmethod
    def list_keys(owner: str, root: Path = KEYS_ROOT) -> List[Dict[str, Any]]:
        """Liệt kê các cặp khóa của người dùng (chỉ đọc phần công khai của .fpk)."""
        pub_dir, priv_dir = KeyStore.user_dirs(owner, root)
        out = []
        if not priv_dir.is_dir():
            return out
        for p in priv_dir.iterdir():
            m = re.match(r"private(\d+)\.fpk$", p.name)
            if not m:
                continue
            idx = int(m.group(1))
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            pub_path = pub_dir / f"key{idx}.hex"
            out.append({
                "index": idx,
                "name": f"key{idx}",
                "algorithm": rec.get("algorithm", "?"),
                "fingerprint": rec.get("fingerprint", ""),
                "created": rec.get("created", ""),
                # Khóa do bản mô phỏng cũ tạo ra (không phải Falcon thật)
                "legacy": rec.get("version", 0) < KeyStore.FORMAT_VERSION,
                "protected": KeyStore.is_protected(rec),
                "private_path": str(p),
                "public_path": str(pub_path) if pub_path.is_file() else "",
            })
        out.sort(key=lambda k: k["index"])
        return out

    @staticmethod
    def save_keypair(sk: bytes, pk: bytes, algorithm: str, password: str, out_path: Path) -> None:
        """password rỗng -> mã hóa bằng chuỗi nội bộ, không cần mật khẩu khi ký."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)

        # Dẫn xuất khóa từ mật khẩu: K = PBKDF2-HMAC-SHA256(password, salt, 100000)
        key = CryptographicPrimitive.pbkdf2_hmac(password or KeyStore.INTERNAL_PASSPHRASE, salt)
        # Mã hóa xác thực AES-256-GCM (bản mã || thẻ 16 byte)
        cipher_sk = AESGCM(key).encrypt(nonce, sk, KeyStore._aad(algorithm))

        record = {
            "version": KeyStore.FORMAT_VERSION,
            "algorithm": algorithm,
            "protected": bool(password),
            "kdf": "PBKDF2-HMAC-SHA256/100000",
            "cipher": "AES-256-GCM",
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext_sk": base64.b64encode(cipher_sk).decode(),
            "public_key": base64.b64encode(pk).decode(),
            "fingerprint": CryptographicPrimitive.hex_sha256(pk),
            "created": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def load_keypair(key_path: Path, password: str = "") -> Tuple[bytes, bytes, str]:
        record = json.loads(key_path.read_text(encoding="utf-8"))
        return KeyStore.decrypt_record(record, password)

    @staticmethod
    def decrypt_record(record: Dict[str, Any], password: str = "") -> Tuple[bytes, bytes, str]:
        """Giải mã bản ghi .fpk (đã đọc thành dict) -> (sk, pk, thuật toán)."""
        if record.get("version", 0) < KeyStore.FORMAT_VERSION:
            raise ValueError(
                "Tệp khóa cũ do bản mô phỏng tạo ra, không dùng được với Falcon thật. "
                "Hãy Sinh Khóa mới!"
            )
        if not KeyStore.is_protected(record):
            password = KeyStore.INTERNAL_PASSPHRASE
        elif not password:
            raise ValueError("Khóa này được bảo vệ bằng mật khẩu - hãy nhập mật khẩu!")
        algorithm = record["algorithm"]
        salt = base64.b64decode(record["salt"])
        nonce = base64.b64decode(record["nonce"])
        cipher_sk = base64.b64decode(record["ciphertext_sk"])
        pk = base64.b64decode(record["public_key"])

        key = CryptographicPrimitive.pbkdf2_hmac(password, salt)
        try:
            sk = AESGCM(key).decrypt(nonce, cipher_sk, KeyStore._aad(algorithm))
        except InvalidTag:
            # Sai mật khẩu (hoặc tệp khóa bị sửa) -> thẻ GCM không khớp
            raise ValueError("Mật khẩu không đúng!") from None

        if len(sk) != FalconNISTParams.PARAMS[algorithm]["sk_byte_len"]:
            raise ValueError("Tệp khóa bí mật bị hỏng!")
        return sk, pk, algorithm

    @staticmethod
    def verify_password(key_path: Path, password: str) -> bool:
        """Chỉ kiểm tra mật khẩu có đúng với tệp .fpk hay không (không trả sk)."""
        try:
            KeyStore.load_keypair(key_path, password)
            return True
        except Exception:
            return False


class KeyInspector:
    """Kiểm tra thuộc tính khóa Falcon: định dạng, tham số và tính hợp lệ toán học.

    - Khóa công khai (.hex): header 0x00+logn, độ dài 897/1793 byte, mọi hệ số h < q.
    - Khóa bí mật (.fpk): thông tin mã hóa (PBKDF2 + AES-256-GCM); nếu có mật khẩu
      thì giải mã và kiểm tra thêm:
        + định dạng sk (header 0x50+logn, 1281/2305 byte)
        + phương trình NTRU  f·G − g·F = q
        + khóa công khai suy ra h = g·f⁻¹ mod q trùng với pk lưu kèm
        + ký thử và xác thực một thông điệp mẫu
    Kết quả là dict gồm "properties" (danh sách nhãn/giá trị) và "checks"
    (danh sách kiểm tra: status = ok / bad / warn / skip).
    """

    @staticmethod
    def _algo_for_pk(pk: bytes) -> Optional[str]:
        for name, p in FalconNISTParams.PARAMS.items():
            if len(pk) == p["pk_byte_len"]:
                return name
        return None

    @staticmethod
    def _base_props(algo: str) -> List[Tuple[str, str]]:
        p = FalconNISTParams.PARAMS[algo]
        level = "1 (≈ AES-128)" if p["n"] == 512 else "5 (≈ AES-256)"
        return [
            ("Thuật toán", f"{algo.replace('_', '-').title()}"),
            ("Mức an toàn NIST", level),
            ("Bậc đa thức n / modulo q", f"{p['n']} / {FalconNISTParams.Q}"),
            ("Kích thước khóa công khai", f"{p['pk_byte_len']} byte"),
            ("Kích thước khóa bí mật", f"{p['sk_byte_len']} byte"),
            ("Kích thước chữ ký", f"{p['sig_byte_len']} byte"),
        ]

    @classmethod
    def inspect_public(cls, pk: bytes) -> Dict[str, Any]:
        checks: List[Dict[str, str]] = []
        algo = cls._algo_for_pk(pk)
        checks.append({"label": "Độ dài khóa công khai", "status": "ok" if algo else "bad",
                       "detail": f"{len(pk)} byte" + ("" if algo else " - không khớp 897 / 1793")})
        props: List[Tuple[str, str]] = []
        if algo:
            p = FalconNISTParams.PARAMS[algo]
            props = cls._base_props(algo)
            header_ok = pk[0] == p["logn"]
            checks.append({"label": "Header khóa công khai", "status": "ok" if header_ok else "bad",
                           "detail": f"0x{pk[0]:02x} (mong đợi 0x{p['logn']:02x})"})
            try:
                FalconEncoding.decode_pk(pk, p["n"], p["logn"])
                checks.append({"label": "Hệ số h ∈ [0, q)", "status": "ok",
                               "detail": f"{p['n']} hệ số 14 bit hợp lệ"})
            except ValueError as e:
                checks.append({"label": "Hệ số h ∈ [0, q)", "status": "bad", "detail": str(e)})
        fp = CryptographicPrimitive.hex_sha256(pk)
        props.append(("Fingerprint (SHA-256)", fp))
        return {"kind": "public", "algorithm": algo, "fingerprint": fp,
                "properties": props, "checks": checks}

    @classmethod
    def inspect_private(cls, record: Dict[str, Any], password: str = "") -> Dict[str, Any]:
        algo = record.get("algorithm", "")
        version = record.get("version", 0)
        try:
            pk = base64.b64decode(record.get("public_key", ""))
        except Exception:
            pk = b""
        res = cls.inspect_public(pk)
        res["kind"] = "private"
        checks = res["checks"]
        props = res["properties"]
        props += [
            ("Định dạng tệp", f"FalconPDFTool v{version}"),
            ("Mã hóa khóa bí mật", record.get("cipher", "—")),
            ("Bảo vệ khóa bí mật", "Mật khẩu người dùng" if KeyStore.is_protected(record)
             else "Khóa nội bộ của ứng dụng (không mật khẩu)"),
            ("Dẫn xuất khóa từ mật khẩu", record.get("kdf", "—")),
            ("Ngày tạo", record.get("created", "—")),
        ]
        if version < KeyStore.FORMAT_VERSION:
            checks.append({"label": "Phiên bản tệp khóa", "status": "bad",
                           "detail": "Khóa cũ (bản mô phỏng) - cần sinh khóa mới"})
            return res
        checks.append({"label": "Phiên bản tệp khóa", "status": "ok", "detail": f"v{version} · AES-256-GCM"})
        if record.get("fingerprint") and record["fingerprint"] != res["fingerprint"]:
            checks.append({"label": "Fingerprint lưu kèm", "status": "bad", "detail": "Không khớp khóa công khai"})

        secret_labels = ["Giải mã khóa bí mật", "Định dạng khóa bí mật", "Phương trình NTRU f·G − g·F = q",
                         "Khóa công khai khớp khóa bí mật", "Ký thử & xác thực"]
        if not password and KeyStore.is_protected(record):
            checks += [{"label": l, "status": "skip", "detail": "Nhập mật khẩu khóa để kiểm tra"} for l in secret_labels]
            return res
        try:
            sk, pk, algo = KeyStore.decrypt_record(record, password)
        except ValueError as e:
            # Sai mật khẩu không có nghĩa là khóa hỏng -> cảnh báo, bỏ qua các bước còn lại
            checks.append({"label": secret_labels[0], "status": "warn", "detail": str(e)})
            checks += [{"label": l, "status": "skip", "detail": "Chưa kiểm tra"} for l in secret_labels[1:]]
            return res
        checks.append({"label": secret_labels[0], "status": "ok", "detail": f"{len(sk)} byte"})
        engine = FalconEngine(algo)
        try:
            f, g, F, G = engine.decode_secret_key(sk)
        except ValueError as e:
            checks.append({"label": secret_labels[1], "status": "bad", "detail": str(e)})
            return res
        checks.append({"label": secret_labels[1], "status": "ok",
                       "detail": f"header 0x{sk[0]:02x}, |f|,|g| ≤ {max(abs(x) for x in f + g)}, |F|,|G| ≤ {max(abs(x) for x in F + G)}"})
        fG = NTRUEngine.poly_mul_int(f, G)
        gF = NTRUEngine.poly_mul_int(g, F)
        diff = [a - b for a, b in zip(fG, gF)]
        ntru_ok = diff[0] == FalconNISTParams.Q and not any(diff[1:])
        checks.append({"label": secret_labels[2], "status": "ok" if ntru_ok else "bad",
                       "detail": f"= {diff[0]}" if ntru_ok else "Không thỏa"})
        pk_ok = engine.public_key_from_secret(sk) == pk
        checks.append({"label": secret_labels[3], "status": "ok" if pk_ok else "bad",
                       "detail": "h = g·f⁻¹ mod q" if pk_ok else "Khác nhau"})
        msg = b"FalconPDFTool key self-test"
        t0 = time.perf_counter()
        sig = engine.sign(sk, msg)
        t1 = time.perf_counter()
        ok = engine.verify(pk, msg, sig)
        t2 = time.perf_counter()
        checks.append({"label": secret_labels[4], "status": "ok" if ok else "bad",
                       "detail": f"ký {(t1 - t0) * 1000:.1f} ms · xác thực {(t2 - t1) * 1000:.1f} ms"})
        sq = sum(x * x for x in f) + sum(x * x for x in g)
        props.append(("Chuẩn ‖(f, g)‖", f"{sq ** 0.5:.1f}"))
        return res


class UserStore:
    """Tài khoản người dùng cho ứng dụng desktop - dùng chung tệp với bản web.

    server_data/users.json:
        { "<tên đăng nhập>": {"fullname", "password_hash", "role": "admin"|"user", "created"} }
    Mật khẩu băm bằng werkzeug (cùng định dạng server.py) -> một tài khoản đăng nhập
    được cả trên web lẫn trên ứng dụng. Tài khoản đầu tiên được tạo là quản trị viên.
    """
    _lock = threading.Lock()

    @staticmethod
    def load() -> Dict[str, Dict[str, Any]]:
        try:
            return json.loads(USERS_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _save(users: Dict[str, Dict[str, Any]]) -> None:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = USERS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(USERS_FILE)

    @classmethod
    def create(cls, username: str, fullname: str, password: str, password2: str,
               role: Optional[str] = None) -> Dict[str, Any]:
        """Tạo tài khoản; role=None -> admin nếu là tài khoản đầu tiên, ngược lại user."""
        from werkzeug.security import generate_password_hash
        username = (username or "").strip()
        if len(username) < 3 or safe_name(username) != username:
            raise ValueError("Tên đăng nhập tối thiểu 3 ký tự, chỉ gồm chữ không dấu, số, dấu _ . -")
        if len(password) < 6:
            raise ValueError("Mật khẩu tối thiểu 6 ký tự.")
        if password != password2:
            raise ValueError("Hai lần nhập mật khẩu không khớp.")
        with cls._lock:
            users = cls.load()
            if username.lower() in (u.lower() for u in users):
                raise ValueError("Tên đăng nhập đã tồn tại.")
            users[username] = {
                "fullname": (fullname or "").strip() or username,
                "password_hash": generate_password_hash(password),
                "role": role or ("admin" if not users else "user"),
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            cls._save(users)
        return dict(users[username], username=username)

    @classmethod
    def authenticate(cls, username: str, password: str) -> Optional[Dict[str, Any]]:
        from werkzeug.security import check_password_hash
        user = cls.load().get((username or "").strip())
        if user and check_password_hash(user.get("password_hash", ""), password):
            return dict(user, username=username.strip())
        return None

    @classmethod
    def set_role(cls, username: str, role: str) -> None:
        with cls._lock:
            users = cls.load()
            if username not in users or role not in ("admin", "user"):
                raise ValueError("Người dùng hoặc quyền không hợp lệ.")
            users[username]["role"] = role
            cls._save(users)

    @classmethod
    def delete(cls, username: str) -> None:
        """Xóa tài khoản (khóa trong keys/<user>/ được giữ lại)."""
        with cls._lock:
            users = cls.load()
            if users.pop(username, None) is None:
                raise ValueError("Không tìm thấy người dùng.")
            cls._save(users)


def safe_name(name: str) -> str:
    """Chuẩn hóa tên người dùng thành tên thư mục an toàn."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", (name or "").strip())
    return cleaned.strip(".") or "default"


# ==============================================================================
#   TẦNG 2. KHỐI CAN THIỆP CẤU TRÚC PDF  (Mục 1.3, 1.4, 2.2.2, 3.2.2)
# ==============================================================================

class StructureEngine:
    @classmethod
    def build_placeholder_pdf(cls, pdf_bytes: bytes, sig_byte_len: int, reason: str, algorithm: str,
                              auth_hash: str = "", signer: str = "") -> Tuple[bytes, int, str, int]:
        """Dựng khung từ điển chữ ký /Sig với placeholder có thể định vị trên byte thô.

        [Đồ án - Mục 1.3] Từ điển chữ ký (/Type /Sig) chứa /Contents (chữ ký Hex)
        và /ByteRange [o1 l1 o2 l2].
        [Đồ án - Mục 2.2.2.a Bước 1] Chèn /Contents toàn ký tự '0' với kích thước
        N = sig_byte_len × 2 + 128; chèn /PQC.Algorithm và /PQC.PublicKey.
        [Đồ án - Mục 3.2.2 Giai đoạn 1 - build_placeholder_pdf]:
          - /Filter /Custom.FalconPQC
          - /Contents mở đầu bằng unique_hex_tag "707163..." ("pqc" ở dạng hex)
          - /PQC.PublicKey placeholder "ff..." đúng độ dài
          - /ByteRange cố định [0000000000 0000000000 0000000000 0000000000]
            (10 chữ số/ số -> thay thế tại chỗ không lệch offset)
          - Siêu dữ liệu /Info: /FalconPQC_Status, _SignDate, _SignatureID,
            _SignedScope, _Algorithm, _AuthHash, _Signer
          - /AcroForm với /SigFlags 3 để Adobe/Foxit nhận diện trường chữ ký
        """
        # Độ dài hex của chữ ký (2 hex chars / byte) + đệm an toàn 128 ký tự
        placeholder_chars = sig_byte_len * 2 + 128

        # Marker chỉ gồm [0-9a-f] để pypdf không escape khi ghi TextStringObject
        unique_hex_tag = "707163" + secrets.token_hex(8)
        # Nội dung placeholder thuần hex (KHÔNG bọc < >) — tránh bị escape \074 \076
        placeholder_hex = unique_hex_tag + "0" * (placeholder_chars - len(unique_hex_tag))

        pk_byte_len = FalconNISTParams.PARAMS.get(algorithm, FalconNISTParams.PARAMS["falcon_512"])["pk_byte_len"]
        pk_placeholder_len = pk_byte_len * 2
        # Marker PK cũng thuần hex
        pk_placeholder_hex = "ff" + "f" * (pk_placeholder_len - 2)

        sig_dict = DictionaryObject()
        sig_dict[NameObject("/Type")] = NameObject("/Sig")
        sig_dict[NameObject("/Filter")] = NameObject("/Custom.FalconPQC")
        sig_dict[NameObject("/SubFilter")] = NameObject("/adbe.pkcs7.detached")

        # Contents: chuỗi hex thuần (sẽ được thay bằng <hex...> trên byte thô)
        sig_dict[NameObject("/Contents")] = TextStringObject(placeholder_hex)
        # ByteRange: chuỗi cố định độ rộng 10 chữ số / số — thay thế in-place không lệch offset
        sig_dict[NameObject("/ByteRange")] = TextStringObject(
            "[0000000000 0000000000 0000000000 0000000000]"
        )
        sig_dict[NameObject("/Reason")] = TextStringObject(reason)
        sig_dict[NameObject("/PQC.Algorithm")] = TextStringObject(algorithm)
        sig_dict[NameObject("/PQC.PublicKey")] = TextStringObject(pk_placeholder_hex)
        if signer:
            sig_dict[NameObject("/Name")] = TextStringObject(signer)

        # PyPDF: PdfReader phân tích cú pháp (Mục 1.4.1.a) -> PdfWriter nhân bản cây đối tượng
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter(clone_from=reader)
        sig_ref = writer._add_object(sig_dict)

        sig_id = f"FALCON-SIG-{secrets.token_hex(4).upper()}"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Siêu dữ liệu /Info (Mục 2.1.2, 3.2.2 Giai đoạn 1) - nằm trong vùng được băm
        info_dict = writer.metadata if writer.metadata else DictionaryObject()
        info_dict[NameObject("/Title")] = TextStringObject(f"Document Signed with {algorithm.upper()}")
        info_dict[NameObject("/Subject")] = TextStringObject(f"PQC Digital Signature - ID: {sig_id}")
        info_dict[NameObject("/Author")] = TextStringObject(signer or "Le Hai Anh - DT060102")
        info_dict[NameObject("/FalconPQC_Status")] = TextStringObject(f"SIGNED_WITH_{algorithm.upper()}")
        info_dict[NameObject("/FalconPQC_SignDate")] = TextStringObject(timestamp)
        info_dict[NameObject("/FalconPQC_SignatureID")] = TextStringObject(sig_id)
        info_dict[NameObject("/FalconPQC_SignedScope")] = TextStringObject(
            "Toan bo noi dung tep PDF tu Byte 0 den Byte END (loai tru vung dem /Contents)"
        )
        info_dict[NameObject("/FalconPQC_Algorithm")] = TextStringObject(
            f"NIST PQC {algorithm.upper()} over NTRU Lattice"
        )
        if signer:
            info_dict[NameObject("/FalconPQC_Signer")] = TextStringObject(signer)
        if auth_hash:
            info_dict[NameObject("/FalconPQC_AuthHash")] = TextStringObject(auth_hash)
        writer.add_metadata(info_dict)

        # Chú thích chữ ký (Signature Annotation - Mục 1.3 Incremental Update)
        annot = DictionaryObject()
        annot[NameObject("/Type")] = NameObject("/Annot")
        annot[NameObject("/Subtype")] = NameObject("/Widget")
        annot[NameObject("/FT")] = NameObject("/Sig")
        annot[NameObject("/T")] = TextStringObject("FalconSig_" + secrets.token_hex(4))
        annot[NameObject("/V")] = sig_ref
        annot[NameObject("/Rect")] = ArrayObject([
            NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)
        ])

        if len(writer.pages) == 0:
            writer.add_blank_page(width=595, height=842)
        if "/Annots" not in writer.pages[0]:
            writer.pages[0][NameObject("/Annots")] = ArrayObject()
        writer.pages[0][NameObject("/Annots")].append(annot)

        # AcroForm để Adobe/Foxit nhận diện trường chữ ký (/SigFlags 3)
        if "/AcroForm" not in writer._root_object:
            writer._root_object[NameObject("/AcroForm")] = DictionaryObject()
        acro = writer._root_object["/AcroForm"]
        if "/Fields" not in acro:
            acro[NameObject("/Fields")] = ArrayObject()
        acro[NameObject("/Fields")].append(annot)
        acro[NameObject("/SigFlags")] = NumberObject(3)

        # Serialize: pypdf sắp xếp lại offset (Mục 1.4.2) -> cần định vị lại trên byte thô
        buf = io.BytesIO()
        writer.write(buf)
        return buf.getvalue(), placeholder_chars, unique_hex_tag, pk_placeholder_len


class ByteRangeBuilder:
    @classmethod
    def compute_byterange(cls, raw_pdf: bytes, placeholder_chars: int, unique_hex_tag: str) -> Tuple[List[int], bytes]:
        """Định vị chính xác vùng Contents placeholder trên byte thô.

        [Đồ án - Mục 1.3] /ByteRange = [o1, l1, o2, l2]:
            o1 = 0 ; l1 = vị trí ngay trước ký tự mở của /Contents
            o2 = vị trí ngay sau ký tự đóng ; l2 = phần còn lại đến hết tệp
        [Đồ án - Mục 2.2.2.a Bước 2, Mục 3.2.2 Giai đoạn 2] Quét byte thô
        (Byte-level Pattern Matching - Mục 1.4.2) tìm unique_hex_tag, mở rộng ra
        cặp ngoặc ( ) bao quanh -> L1, L2; sau đó vùng này sẽ được thay bằng <hex>.
        """
        tag_bytes = unique_hex_tag.encode("latin-1")
        idx = raw_pdf.find(tag_bytes)
        if idx < 0:
            raise RuntimeError(
                "Loi dinh vi dem Placeholder /Contents trong PDF tho! "
                "Marker khong ton tai — co the pypdf da escape ky tu."
            )

        # Tìm dấu '(' mở của literal string chứa marker
        open_paren = raw_pdf.rfind(b"(", 0, idx)
        if open_paren < 0:
            raise RuntimeError("Khong tim thay '(' mo dau Contents string!")

        # Tìm ')' đóng tương ứng (Contents chỉ chứa [0-9a-f] nên không có nested)
        close_paren = raw_pdf.find(b")", idx)
        if close_paren < 0:
            raise RuntimeError("Khong tim thay ')' dong Contents string!")

        # Vùng sẽ bị thay thế: từ '(' đến ')' inclusive
        region_start = open_paren          # = L1
        region_end = close_paren + 1       # = L2 (exclusive)

        byterange = [0, region_start, region_end, len(raw_pdf) - region_end]
        msg_bytes = raw_pdf[0:region_start] + raw_pdf[region_end:]
        return byterange, msg_bytes


class StructureEngineInject:
    @classmethod
    def inject_falcon_signature(
        cls,
        raw_pdf: bytes,
        byterange: List[int],
        signature: bytes,
        pk_hex: str,
        pk_placeholder_len: int,
    ) -> bytes:
        """Ghi chữ ký vào vùng đệm /Contents (dạng <hex>) và ghi PublicKey.

        [Đồ án - Mục 2.2.2.a Bước 6] Mã hóa σ sang Hex, ghi trực tiếp vào đúng
        byte offset của vùng đệm /Contents.
        [Đồ án - Mục 2.3.2 "Signature Injection"] Độ dài thay thế == độ dài
        placeholder -> không xáo trộn con trỏ byte trong bảng XRef.
        `signature` ở đây có thể kèm phần đuôi thời gian ký (SIGN_TIME_MARKER).
        """
        sig_offset = byterange[1]
        sig_end = byterange[2]
        placeholder_len = sig_end - sig_offset

        inner_hex_len = placeholder_len - 2   # trừ 2 ký tự '<' '>'
        if inner_hex_len < len(signature) * 2:
            raise RuntimeError(
                f"Vung dem Contents qua nho: can {len(signature)*2}, co {inner_hex_len}"
            )
        sig_hex = signature.hex().ljust(inner_hex_len, "0")
        replacement = b"<" + sig_hex.encode("latin-1") + b">"
        if len(replacement) != placeholder_len:
            raise RuntimeError(
                f"replacement {len(replacement)} != placeholder {placeholder_len}"
            )

        signed_pdf = raw_pdf[:sig_offset] + replacement + raw_pdf[sig_end:]

        # Public Key: thông thường đã được ghi TRƯỚC khi băm (xem sign_pdf).
        # Nhánh dưới chỉ chạy khi placeholder PK vẫn còn (dự phòng).
        target_pk = ("ff" + "f" * (pk_placeholder_len - 2)).encode("latin-1")
        real_pk = pk_hex.encode("latin-1")
        if len(real_pk) > len(target_pk):
            real_pk = real_pk[: len(target_pk)]
        else:
            real_pk = real_pk.ljust(len(target_pk), b"0")
        if target_pk not in signed_pdf:
            target_pk = b"f" * pk_placeholder_len
            real_pk = pk_hex.encode("latin-1").ljust(pk_placeholder_len, b"0")[:pk_placeholder_len]
        if target_pk in signed_pdf:
            # PK nằm ngoài /Contents -> thay đổi PK sau khi băm sẽ phá chữ ký,
            # nên sign_pdf luôn ghi PK TRƯỚC khi băm (Pre-hash Injection - Mục 3.2.2).
            signed_pdf = signed_pdf.replace(target_pk, real_pk, 1)

        return signed_pdf


# ==============================================================================
#   ĐIỀU PHỐI QUY TRÌNH (Mục 2.2.2, 3.3)
# ==============================================================================

class FalconPDFTool:
    def __init__(self, algorithm: str = "falcon_512"):
        self.algorithm = algorithm
        self.engine = FalconEngine(algorithm)

    def keygen(self, password: str = "", owner: str = "default", root: Union[str, Path] = KEYS_ROOT) -> Dict[str, Any]:
        """Quy trình sinh khóa (Mục 3.3 "Quy trình sinh khóa").

        Gọi FalconEngine.keygen() -> (sk, pk); sk được mã hóa AES-256-GCM (mặc
        định bằng khóa nội bộ, không cần mật khẩu) và lưu thành privateN.fpk
        trong thư mục private/, pk xuất dạng Hex thành keyN.hex trong public/.
        """
        root = Path(root)
        pub_dir, priv_dir = KeyStore.user_dirs(owner, root)
        pub_dir.mkdir(parents=True, exist_ok=True)
        priv_dir.mkdir(parents=True, exist_ok=True)

        idx = KeyStore.next_index(owner, root)
        sk_path = priv_dir / f"private{idx}.fpk"
        pk_path = pub_dir / f"key{idx}.hex"

        t0 = time.perf_counter()
        sk, pk = self.engine.keygen()
        keygen_ms = (time.perf_counter() - t0) * 1000.0

        KeyStore.save_keypair(sk, pk, self.algorithm, password, sk_path)
        pk_path.write_text(pk.hex(), encoding="utf-8")
        return {
            "index": idx,
            "algorithm": self.algorithm,
            "private_path": str(sk_path),
            "public_path": str(pk_path),
            "fingerprint": CryptographicPrimitive.hex_sha256(pk),
            "keygen_time_ms": round(keygen_ms, 2),
        }

    def sign_pdf(
        self,
        pdf_path: str,
        key_path: str,
        out_path: str,
        password: str = "",
        reason: str = "Ky so PDF Falcon",
        signer: str = "",
    ) -> Dict[str, Any]:
        """Quy trình ký số PDF - 6 bước (Mục 2.2.2.a, Hình 2.1; Mục 3.2.2; Mục 3.3).

          Bước 0  Giải mã khóa bí mật (.fpk) - chỉ cần mật khẩu với khóa cũ có mật khẩu
          Bước 1  Dựng khung /Sig + placeholder /Contents  -> StructureEngine
          Bước 2  Tính /ByteRange [0, L1, L2, L3]          -> ByteRangeBuilder
                  + Pre-hash Injection: ghi ByteRange & PublicKey thật TRƯỚC khi băm
          Bước 3  Data_signed = File[0..L1] || File[L2..L2+L3]
          Bước 4-5 Băm & ký Falcon                           -> FalconEngine.sign
          Bước 6  Ghi chữ ký Hex vào /Contents                -> StructureEngineInject
        """
        key_path_obj = Path(key_path)
        if not key_path_obj.is_file():
            raise ValueError(f"Không tìm thấy tệp khóa: {key_path}")

        # Bước 0: Giải mã khóa bí mật (khóa có mật khẩu: sai mật khẩu thì dừng, không ký)
        try:
            sk, pk, algo = KeyStore.load_keypair(key_path_obj, password)
        except ValueError as e:
            raise ValueError(str(e)) from e
        except Exception as e:
            raise ValueError(
                f"Không thể mở khóa: {e}. Kiểm tra mật khẩu và tệp .fpk!"
            ) from e

        self.algorithm = algo
        self.engine = FalconEngine(algo)
        # Đối chiếu: khóa công khai suy ra từ sk (h = g·f⁻¹) phải trùng pk lưu kèm
        if self.engine.public_key_from_secret(sk) != pk:
            raise ValueError("Tệp khóa bị hỏng: khóa bí mật và khóa công khai không khớp!")

        # Băm mật khẩu để nhúng vào PDF (/FalconPQC_AuthHash) - chỉ với khóa có mật khẩu
        auth_hash = PasswordManager.hash_password(password) if password else ""

        # Bước 1: Dựng khung cấu trúc & Placeholder
        pdf_bytes = Path(pdf_path).read_bytes()
        raw_ph, ph_chars, unique_tag, pk_ph_len = StructureEngine.build_placeholder_pdf(
            pdf_bytes, self.engine.params["sig_byte_len"], reason, algo,
            auth_hash=auth_hash, signer=signer,
        )
        # Bước 2: Xác định dải /ByteRange
        byterange, _ = ByteRangeBuilder.compute_byterange(raw_ph, ph_chars, unique_tag)

        # Pre-hash Injection (Mục 3.2.2): ghi ByteRange ĐÚNG trước khi băm.
        # pypdf ghi '[' ']' trong chuỗi literal dưới dạng octal \133 \135.
        L0, L1, L2 = 0, byterange[1], byterange[2]
        L3 = len(raw_ph) - L2
        old_br = b"\\1330000000000 0000000000 0000000000 0000000000\\135"
        new_br = f"\\133{L0:010d} {L1:010d} {L2:010d} {L3:010d}\\135".encode("latin-1")
        if old_br not in raw_ph:
            raise RuntimeError("Không tìm thấy ByteRange placeholder để cập nhật trước khi ký!")
        raw_ready = raw_ph.replace(old_br, new_br, 1)

        # Pre-hash Injection: ghi PublicKey thật TRƯỚC khi băm (PK nằm trong vùng được ký)
        target_pk = ("ff" + "f" * (pk_ph_len - 2)).encode("latin-1")
        real_pk = pk.hex().encode("latin-1")
        if len(real_pk) > len(target_pk):
            real_pk = real_pk[: len(target_pk)]
        else:
            real_pk = real_pk.ljust(len(target_pk), b"0")
        if target_pk in raw_ready:
            raw_ready = raw_ready.replace(target_pk, real_pk, 1)
        byterange = [L0, L1, L2, L3]

        # Bước 3: Trích xuất phân đoạn byte (loại trừ vùng /Contents)
        msg_to_sign = raw_ready[0:L1] + raw_ready[L2:]

        # Bước 4: Băm thông điệp H = SHA-256(Data_signed)
        # Bước 5: Ký Falcon trên H: salt r, c = HashToPoint(r || H), ffSampling,
        #         kiểm tra β², σ = header || r || Compress(s2)
        # Đo thời gian ký để hiển thị "Ký trong ... ms"
        t0 = time.perf_counter()
        doc_hash = CryptographicPrimitive.sha256(msg_to_sign)
        signature = self.engine.sign(sk, doc_hash)
        dt_ms = (time.perf_counter() - t0) * 1000.0

        # Phần đuôi thời gian ký nằm trong /Contents (ngoài ByteRange -> không ảnh hưởng băm)
        contents_payload = signature + SIGN_TIME_MARKER + struct.pack(">d", dt_ms)

        # Bước 6: Ghi bổ sung chữ ký vào Placeholder
        signed_bytes = StructureEngineInject.inject_falcon_signature(
            raw_ready, byterange, contents_payload, pk.hex(), pk_ph_len
        )
        Path(out_path).write_bytes(signed_bytes)

        return {
            "algorithm": algo,
            "sig_bytes_len": len(signature),
            "sign_time_ms": round(dt_ms, 2),
            "output_pdf": out_path,
            "pk_fingerprint": CryptographicPrimitive.hex_sha256(pk),
            "byterange": byterange,
        }

    def verify_pdf(self, pdf_path: str, password: str = "") -> Dict[str, Any]:
        """Xác thực chữ ký Falcon - 6 bước (Mục 2.2.2.b, Hình 2.2; Mục 3.3).

          Bước 1  Định vị /Sig, trích /ByteRange (hỗ trợ dạng chuẩn, dạng ngoặc
                  đơn và dạng octal \\133..\\135 do pypdf tạo) và /Contents
          Bước 2  Giải mã Hex /Contents -> σ = header || r || Compress(s2) + thời gian ký
          Bước 3  Đọc dữ liệu byte theo đúng /ByteRange
          Bước 4  H' = SHA-256(dữ liệu dải byte)
          Bước 5-6 FalconEngine.verify: c' = HashToPoint(r || H'), giải nén s2,
                  s1 = c' − s2·h mod q, chấp nhận khi ‖(s1, s2)‖² ≤ β²
        Trả về thêm sign_time_ms (Ký trong ... ms) và verify_time_ms.
        """
        t_verify0 = time.perf_counter()
        raw_pdf = Path(pdf_path).read_bytes()

        def fail(error: str, **extra) -> Dict[str, Any]:
            base = {
                "valid": False,
                "error": error,
                "pqc_status": "None",
                "sign_date": "None",
                "algorithm": "None",
                "pk_fingerprint": "None",
                "pk_fingerprint_full": "",
                "signer": "",
                "sign_time_ms": None,
                "verify_time_ms": round((time.perf_counter() - t_verify0) * 1000.0, 2),
            }
            base.update(extra)
            return base

        # Bước 1a: Trích xuất ByteRange.
        # Tệp được ký lại (ký một PDF đã ký) chứa nhiều từ điển /Sig; chữ ký cũ mất
        # hiệu lực vì pypdf ghi lại toàn bộ tệp -> chỉ xác thực chữ ký MỚI NHẤT
        # (ByteRange cuối cùng) và đọc /Contents, /PQC.* trong CÙNG đối tượng đó.
        m = None
        for pattern in (
            rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]",
            rb"/ByteRange\s*\(\\133(\d{10}) (\d{10}) (\d{10}) (\d{10})\\135\)",
            rb"/ByteRange\s*\(\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]\s*\)",
        ):
            for found in re.finditer(pattern, raw_pdf):
                if m is None or found.start() > m.start():
                    m = found
        if not m:
            return fail("Tệp không chứa dải ByteRange hoặc chưa được ký số!")

        br = [int(m.group(i)) for i in range(1, 5)]
        if br[1] == 0 and br[2] == 0:
            return fail("ByteRange vẫn là placeholder [0 0 0 0] — quá trình inject thất bại!")

        # Phạm vi đối tượng /Sig chứa ByteRange: từ "N 0 obj" trước đó đến "endobj" sau đó
        obj_start = max(raw_pdf.rfind(b" obj", 0, m.start()), 0)
        obj_end = raw_pdf.find(b"endobj", m.end())
        sig_obj = raw_pdf[obj_start: obj_end if obj_end > 0 else len(raw_pdf)]

        # Bước 1b: Contents (chuỗi Hex chữ ký)
        sig_hex = ""
        contents_match = re.search(rb"/Contents\s*<([0-9a-fA-F]+)>", sig_obj)
        if contents_match:
            sig_hex = contents_match.group(1).decode("latin-1")
        else:
            contents_match = re.search(rb"/Contents\s*\(([0-9a-fA-F]+)\)", sig_obj)
            if contents_match:
                sig_hex = contents_match.group(1).decode("latin-1")

        # Khóa công khai /PQC.PublicKey
        pk_hex = ""
        pk_match = re.search(rb"/PQC\.PublicKey\s*\(([0-9a-fA-F]+)\)", sig_obj)
        if pk_match:
            pk_hex = pk_match.group(1).decode("latin-1")
        else:
            pk_match = re.search(rb"/PQC\.PublicKey\s*<([0-9a-fA-F]+)>", sig_obj)
            if pk_match:
                pk_hex = pk_match.group(1).decode("latin-1")

        # Thuật toán /PQC.Algorithm
        algo = ""
        algo_match = re.search(rb"/PQC\.Algorithm\s*\(([^)]+)\)", sig_obj)
        if algo_match:
            algo = algo_match.group(1).decode("latin-1").strip()

        # Siêu dữ liệu (Mục 2.1.2 - PyPDF đọc /Info qua reader.metadata)
        pqc_status = "UNKNOWN"
        sign_date = "N/A"
        signer = ""
        try:
            reader = PdfReader(io.BytesIO(raw_pdf))
            meta = reader.metadata
            if meta:
                for k, v in meta.items():
                    key_str = str(k)
                    if "FalconPQC_Status" in key_str:
                        pqc_status = str(v)
                    elif "FalconPQC_SignDate" in key_str:
                        sign_date = str(v)
                    elif "FalconPQC_Signer" in key_str:
                        signer = str(v)
        except Exception:
            pass

        if pqc_status == "UNKNOWN":
            status_m = re.search(rb"/FalconPQC_Status\s*\(([^)]*)\)", raw_pdf)
            if status_m:
                pqc_status = status_m.group(1).decode("latin-1", errors="replace")
        if sign_date == "N/A":
            date_m = re.search(rb"/FalconPQC_SignDate\s*\(([^)]*)\)", raw_pdf)
            if date_m:
                sign_date = date_m.group(1).decode("latin-1", errors="replace")

        pk_hex = re.sub(r"[^0-9a-fA-F]", "", pk_hex)
        sig_hex = re.sub(r"[^0-9a-fA-F]", "", sig_hex)

        if not pk_hex or not sig_hex:
            return fail("Không trích xuất được Chữ ký hoặc Public Key!",
                        pqc_status=pqc_status, sign_date=sign_date,
                        algorithm=algo or "None", signer=signer)

        if "1024" in (algo or "") or len(pk_hex) >= 3000:
            algo = "falcon_1024"
        else:
            algo = "falcon_512"

        real_sig_len = FalconNISTParams.PARAMS[algo]["sig_byte_len"]
        real_pk_len = FalconNISTParams.PARAMS[algo]["pk_byte_len"]

        # Bước 2: Giải mã Hex -> σ (+ phần đuôi thời gian ký nếu có)
        try:
            pk_bytes = bytes.fromhex(pk_hex)[:real_pk_len]
            contents_bytes = bytes.fromhex(sig_hex if len(sig_hex) % 2 == 0 else sig_hex[:-1])
            sig_bytes = contents_bytes[:real_sig_len]
        except ValueError:
            return fail("Hex chữ ký / public key không hợp lệ!",
                        pqc_status=pqc_status, sign_date=sign_date, algorithm=algo, signer=signer)

        sign_time_ms = None
        trailer = contents_bytes[real_sig_len:]
        if trailer.startswith(SIGN_TIME_MARKER) and len(trailer) >= len(SIGN_TIME_MARKER) + 8:
            sign_time_ms = round(struct.unpack(">d", trailer[4:12])[0], 2)

        # Bước 3: Đọc dữ liệu byte theo ByteRange
        if br[0] + br[1] > len(raw_pdf) or br[2] + br[3] > len(raw_pdf):
            return fail("ByteRange vượt quá kích thước tệp!",
                        pqc_status=pqc_status, sign_date=sign_date, algorithm=algo, signer=signer)
        msg_bytes = raw_pdf[br[0] : br[0] + br[1]] + raw_pdf[br[2] : br[2] + br[3]]

        # Bước 4: H' = SHA-256(dữ liệu) ; Bước 5-6: Falcon verify với khóa công khai h
        engine = FalconEngine(algo)
        doc_hash = CryptographicPrimitive.sha256(msg_bytes)
        is_valid = engine.verify(pk_bytes, doc_hash, sig_bytes)
        verify_ms = (time.perf_counter() - t_verify0) * 1000.0

        fp_full = CryptographicPrimitive.hex_sha256(pk_bytes)
        return {
            "valid": is_valid,
            "algorithm": algo,
            "sig_len": len(sig_bytes),
            "pqc_status": pqc_status,
            "sign_date": sign_date,
            "signer": signer,
            "pk_fingerprint": fp_full[:16],
            "pk_fingerprint_full": fp_full,
            "sign_time_ms": sign_time_ms,
            "verify_time_ms": round(verify_ms, 2),
            "byterange": br,
            "error": "" if is_valid else "Chữ ký không khớp hoặc tài liệu đã bị sửa!"
        }

    def extract_text_and_properties(self, pdf_path: str) -> Dict[str, Any]:
        """Trích xuất văn bản UTF-8 và Siêu dữ liệu.

        [Đồ án - Mục 1.4.1.b, Mục 2.1.2]:
          - Metadata: PdfReader đọc từ điển /Info (reader.metadata)
          - Văn bản: page.extract_text() -> giải nén /Contents (FlateDecode),
            phân tích toán tử BT/ET/Tf/Tj/TJ, tra /ToUnicode CMap -> UTF-8
        """
        raw_pdf = Path(pdf_path).read_bytes()
        reader = PdfReader(io.BytesIO(raw_pdf))

        full_text = []
        for i, page in enumerate(reader.pages):
            full_text.append(f"--- TRANG {i+1} ---\n" + (page.extract_text() or ""))

        meta = reader.metadata or {}

        def get_meta_value(target_key: str) -> str:
            for k, v in meta.items():
                if target_key in str(k):
                    return str(v)
            return "N/A"

        properties = {
            "Title": get_meta_value("Title"),
            "Subject": get_meta_value("Subject"),
            "Author": get_meta_value("Author"),
            "FalconPQC_Status": get_meta_value("FalconPQC_Status"),
            "FalconPQC_SignDate": get_meta_value("FalconPQC_SignDate"),
            "FalconPQC_SignatureID": get_meta_value("FalconPQC_SignatureID"),
            "FalconPQC_Signer": get_meta_value("FalconPQC_Signer"),
            "FalconPQC_SignedScope": get_meta_value("FalconPQC_SignedScope"),
            "FalconPQC_Algorithm": get_meta_value("FalconPQC_Algorithm"),
        }

        return {
            "total_pages": len(reader.pages),
            "properties": properties,
            "text": "\n".join(full_text)
        }


# ==============================================================================
#   TẦNG 1. GIAO DIỆN ĐỒ HỌA (Mục 2.3.1 Tầng 1, Mục 3.3)
# ==============================================================================

class Theme:
    # Tông sáng, tương phản cao: chữ gần đen trên nền trắng, viền xám đậm
    # -> ảnh chụp màn hình in ra (kể cả in đen trắng) vẫn đọc rõ.
    BG = "#f3f5f8"
    CARD = "#ffffff"
    HEADER_BG = "#ffffff"
    HEADER = "#0b2e5c"
    HEADER_SUB = "#2b2f36"
    ACCENT = "#0b4fa8"
    ACCENT_DARK = "#083b7e"
    TEXT = "#111111"
    MUTED = "#333d4a"
    BORDER = "#8c97a6"
    GHOST = "#e4e8ee"
    OK = "#0d6b2b"
    ERR = "#b3001b"
    FONT = "Segoe UI"
    SIZE = 12           # cỡ chữ cơ bản (pt)
    INPUT = (FONT, 12)
    MONO = ("Consolas", 12)


def _center_on_parent(win, parent) -> None:
    win.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - win.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - win.winfo_height()) // 3
    win.geometry(f"+{max(x, 0)}+{max(y, 0)}")


def ask_yes_no(parent, title: str, message: str) -> bool:
    """Hộp thoại xác nhận với 2 nút tiếng Việt "Có" / "Không"."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.configure(bg=Theme.CARD)
    dlg.resizable(False, False)
    dlg.transient(parent)
    dlg.grab_set()
    answer = {"v": False}

    body = ttk.Frame(dlg, style="Card.TFrame", padding=20)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=title, style="DialogTitle.TLabel").pack(anchor="w")
    ttk.Label(body, text=message, style="Card.TLabel", wraplength=420).pack(anchor="w", pady=(10, 18))

    def choose(v: bool):
        answer["v"] = v
        dlg.destroy()

    row = ttk.Frame(body, style="Card.TFrame")
    row.pack(fill="x")
    ttk.Button(row, text="Không", style="Ghost.TButton", command=lambda: choose(False)).pack(side="right", padx=(6, 0))
    yes = ttk.Button(row, text="Có", style="Accent.TButton", command=lambda: choose(True))
    yes.pack(side="right")
    yes.focus_set()
    dlg.bind("<Return>", lambda e: choose(True))
    dlg.bind("<Escape>", lambda e: choose(False))
    _center_on_parent(dlg, parent)
    parent.wait_window(dlg)
    return answer["v"]


def _setup_styles(root) -> None:
    style = ttk.Style(root)
    style.theme_use("clam")
    f, s = Theme.FONT, Theme.SIZE
    root.configure(bg=Theme.BG)
    style.configure(".", font=(f, s), background=Theme.BG, foreground=Theme.TEXT)
    style.configure("TFrame", background=Theme.BG)
    style.configure("Card.TFrame", background=Theme.CARD)
    style.configure("Header.TFrame", background=Theme.HEADER_BG)
    style.configure("Header.TLabel", background=Theme.HEADER_BG, foreground=Theme.HEADER, font=(f, s + 9, "bold"))
    style.configure("HeaderSub.TLabel", background=Theme.HEADER_BG, foreground=Theme.HEADER_SUB, font=(f, s))
    style.configure("Card.TLabel", background=Theme.CARD, foreground=Theme.TEXT, font=(f, s))
    style.configure("Muted.TLabel", background=Theme.CARD, foreground=Theme.MUTED, font=(f, s - 1))
    style.configure("CardTitle.TLabel", background=Theme.CARD, foreground=Theme.HEADER, font=(f, s + 3, "bold"))
    style.configure("DialogTitle.TLabel", background=Theme.CARD, foreground=Theme.HEADER, font=(f, s + 3, "bold"))
    style.configure("Error.TLabel", background=Theme.CARD, foreground=Theme.ERR, font=(f, s - 1, "bold"))
    style.configure("Footer.TLabel", background=Theme.BG, foreground=Theme.MUTED, font=(f, s - 1))
    style.configure("TEntry", fieldbackground="white", foreground=Theme.TEXT, bordercolor=Theme.BORDER,
                    lightcolor=Theme.BORDER, darkcolor=Theme.BORDER, padding=6)
    style.configure("TCombobox", fieldbackground="white", foreground=Theme.TEXT, bordercolor=Theme.BORDER,
                    lightcolor=Theme.BORDER, darkcolor=Theme.BORDER, padding=5)
    style.map("TCombobox", fieldbackground=[("readonly", "white")], foreground=[("readonly", Theme.TEXT)])
    root.option_add("*TCombobox*Listbox.font", Theme.INPUT)
    style.configure("Accent.TButton", background=Theme.ACCENT, foreground="white",
                    font=(f, s, "bold"), padding=(18, 8), borderwidth=0)
    style.map("Accent.TButton", background=[("active", Theme.ACCENT_DARK), ("disabled", "#9db7e0")])
    style.configure("Ghost.TButton", background=Theme.GHOST, foreground=Theme.TEXT, font=(f, s),
                    padding=(14, 7), borderwidth=1, bordercolor=Theme.BORDER,
                    lightcolor=Theme.GHOST, darkcolor=Theme.GHOST)
    style.map("Ghost.TButton", background=[("active", "#d3d9e2")])
    style.configure("HeaderUser.TLabel", background=Theme.HEADER_BG, foreground=Theme.HEADER, font=(f, s, "bold"))
    style.configure("HeaderRole.TLabel", background=Theme.HEADER_BG, foreground=Theme.MUTED, font=(f, s - 2))
    style.configure("Link.TButton", background=Theme.CARD, foreground=Theme.ACCENT, font=(f, s - 1, "underline"),
                    borderwidth=0, padding=(0, 2))
    style.map("Link.TButton", background=[("active", Theme.CARD)], foreground=[("active", Theme.ACCENT_DARK)])
    rowh = int(root.winfo_fpixels("1i") / 96.0 * 30)
    style.configure("Treeview", font=(f, s - 1), rowheight=rowh, fieldbackground="white",
                    bordercolor=Theme.BORDER, lightcolor=Theme.BORDER, darkcolor=Theme.BORDER)
    style.configure("Treeview.Heading", font=(f, s - 1, "bold"), background=Theme.GHOST, foreground=Theme.TEXT)
    style.map("Treeview", background=[("selected", Theme.ACCENT)], foreground=[("selected", "white")])


def _build_footer(root) -> None:
    """Góc dưới bên phải: tên SV, GVHD, rồi email • địa chỉ • số điện thoại."""
    footer = ttk.Frame(root, padding=(14, 4))
    footer.pack(fill="x", side="bottom")
    contact = ttk.Frame(footer)
    contact.pack(side="right")
    ttk.Label(contact, text="Lê Hải Anh - DT060102 - Học viện Kỹ thuật Mật mã", style="Footer.TLabel").pack(anchor="e")
    ttk.Label(contact, text=f"GVHD: {AUTHOR_SUPERVISOR}", style="Footer.TLabel").pack(anchor="e")
    ttk.Label(contact, text=f"✉ {AUTHOR_EMAIL}   •   📍 {AUTHOR_ADDRESS}   •   ☎ {AUTHOR_PHONE}",
              style="Footer.TLabel").pack(anchor="e")


def _labeled_entry(parent, row: int, label: str, show: str = "") -> tk.StringVar:
    var = tk.StringVar()
    ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=(6, 2))
    entry = ttk.Entry(parent, textvariable=var, show=show, width=34, font=Theme.INPUT)
    entry.grid(row=row + 1, column=0, sticky="ew")
    var.entry = entry  # type: ignore[attr-defined]
    return var


def _login_window() -> Optional[Dict[str, Any]]:
    """Màn hình Đăng nhập / Tạo tài khoản. Trả về người dùng, hoặc None nếu đóng cửa sổ."""
    root = tk.Tk()
    root.title(f"Đăng nhập - Falcon PDF Tool {APP_VERSION}")
    root.resizable(False, False)
    _setup_styles(root)
    result: Dict[str, Any] = {}
    no_users = not UserStore.load()

    head = ttk.Frame(root, style="Header.TFrame", padding=(28, 16))
    head.pack(fill="x")
    ttk.Label(head, text="Falcon PDF Tool", style="Header.TLabel").pack(anchor="w")
    ttk.Label(head, text="Ký số PDF hậu lượng tử", style="HeaderSub.TLabel").pack(anchor="w")
    tk.Frame(root, bg=Theme.ACCENT, height=4).pack(fill="x")
    _build_footer(root)

    outer = tk.Frame(root, bg=Theme.BORDER)
    outer.pack(padx=28, pady=20)
    body = ttk.Frame(outer, style="Card.TFrame", padding=(26, 18))
    body.pack(padx=1, pady=1)
    body.columnconfigure(0, weight=1)

    title_var, sub_var, err_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
    ttk.Label(body, textvariable=title_var, style="DialogTitle.TLabel").grid(row=0, column=0, sticky="w")
    ttk.Label(body, textvariable=sub_var, style="Muted.TLabel", wraplength=380).grid(row=1, column=0, sticky="w", pady=(0, 6))

    fullname = _labeled_entry(body, 2, "Họ và tên")
    username = _labeled_entry(body, 4, "Tên đăng nhập")
    password = _labeled_entry(body, 6, "Mật khẩu", show="•")
    password2 = _labeled_entry(body, 8, "Nhập lại mật khẩu", show="•")
    # Các ô chỉ hiện khi tạo tài khoản. Lưu sẵn danh sách widget: sau grid_remove(),
    # widget không còn trong grid_slaves() nên không thể tìm lại theo số dòng.
    register_only = [w for w in body.grid_slaves() if int(w.grid_info()["row"]) in (2, 3, 8, 9)]

    ttk.Label(body, textvariable=err_var, style="Error.TLabel", wraplength=380).grid(row=10, column=0, sticky="w", pady=(8, 0))
    submit = ttk.Button(body, style="Accent.TButton")
    submit.grid(row=11, column=0, sticky="ew", pady=(8, 4))
    # Chuyển giữa Đăng nhập và Tự tạo tài khoản (nút rõ ràng, không phải link nhỏ)
    tk.Frame(body, bg=Theme.BORDER, height=1).grid(row=12, column=0, sticky="ew", pady=(14, 10))
    switch_hint = tk.StringVar()
    ttk.Label(body, textvariable=switch_hint, style="Muted.TLabel").grid(row=13, column=0)
    switch = ttk.Button(body, style="Ghost.TButton")
    switch.grid(row=14, column=0, sticky="ew", pady=(4, 0))
    mode = {"v": "login"}

    def recenter():
        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_width()) // 2
        y = max((root.winfo_screenheight() - root.winfo_height()) // 3, 0)
        # Không để mép dưới (nút bấm) tràn khỏi màn hình
        y = min(y, max(root.winfo_screenheight() - root.winfo_height() - 60, 0))
        root.geometry(f"+{max(x, 0)}+{y}")

    def set_mode(m: str):
        mode["v"] = m
        err_var.set("")
        reg = m == "register"
        for w in register_only:
            w.grid() if reg else w.grid_remove()
        title_var.set("Tạo tài khoản" if reg else "Đăng nhập")
        sub_var.set(("Tài khoản đầu tiên sẽ là quản trị viên." if no_users else "Mỗi người tự tạo tài khoản riêng.")
                    if reg else "Dùng chung tài khoản với bản web.")
        submit.configure(text="Tạo tài khoản" if reg else "Đăng nhập")
        switch_hint.set("Đã có tài khoản?" if reg else "Chưa có tài khoản?")
        switch.configure(text="Quay lại đăng nhập" if reg else "Tạo tài khoản mới")
        (fullname if reg else username).entry.focus_set()
        recenter()

    def do_submit(_e=None):
        try:
            if mode["v"] == "register":
                UserStore.create(username.get(), fullname.get(), password.get(), password2.get())
            user = UserStore.authenticate(username.get(), password.get())
            if not user:
                raise ValueError("Sai tên đăng nhập hoặc mật khẩu.")
        except ValueError as e:
            err_var.set(str(e))
            return
        result["user"] = user
        root.destroy()

    submit.configure(command=do_submit)
    switch.configure(command=lambda: set_mode("login" if mode["v"] == "register" else "register"))
    root.bind("<Return>", do_submit)
    set_mode("register" if no_users else "login")
    root.mainloop()
    return result.get("user")


def _users_dialog(parent, me: str) -> None:
    """Quản lý người dùng (chỉ quản trị viên): xem, đổi quyền, xóa. Người dùng tự tạo tài khoản ở màn hình đăng nhập."""
    dlg = tk.Toplevel(parent)
    dlg.title("Quản lý người dùng")
    dlg.configure(bg=Theme.CARD)
    dlg.transient(parent)
    dlg.grab_set()

    body = ttk.Frame(dlg, style="Card.TFrame", padding=20)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text="Người dùng", style="DialogTitle.TLabel").pack(anchor="w")
    count_var = tk.StringVar()
    ttk.Label(body, textvariable=count_var, style="Muted.TLabel").pack(anchor="w", pady=(0, 10))

    cols = [("username", "Tên đăng nhập", 150), ("fullname", "Họ và tên", 190),
            ("role", "Quyền", 120), ("keys", "Số khóa", 80), ("created", "Ngày tạo", 170)]
    tree = ttk.Treeview(body, columns=[c[0] for c in cols], show="headings", height=9, selectmode="browse")
    for key, text, width in cols:
        tree.heading(key, text=text, anchor="w")
        tree.column(key, width=width, anchor="w")
    tree.pack(fill="both", expand=True)
    err_var = tk.StringVar()
    ttk.Label(body, textvariable=err_var, style="Error.TLabel").pack(anchor="w", pady=(6, 0))

    def refresh(select: Optional[str] = None):
        tree.delete(*tree.get_children())
        users = UserStore.load()
        for name, u in sorted(users.items()):
            role = "Quản trị viên" if u.get("role") == "admin" else "Người dùng"
            tree.insert("", "end", iid=name, values=(name + (" (bạn)" if name == me else ""), u.get("fullname", ""),
                                                     role, len(KeyStore.list_keys(name)), u.get("created", "")))
        count_var.set(f"{len(users)} tài khoản · người dùng tự đăng ký ở màn hình đăng nhập")
        if select and tree.exists(select):
            tree.selection_set(select)

    def selected() -> Optional[str]:
        sel = tree.selection()
        if not sel:
            err_var.set("Hãy chọn một người dùng trong danh sách.")
            return None
        err_var.set("")
        return sel[0]

    def do_role():
        name = selected()
        if not name:
            return
        if name == me:
            err_var.set("Không thể tự đổi quyền của chính mình.")
            return
        new = "user" if UserStore.load().get(name, {}).get("role") == "admin" else "admin"
        UserStore.set_role(name, new)
        refresh(name)

    def do_delete():
        name = selected()
        if not name:
            return
        if name == me:
            err_var.set("Không thể xóa tài khoản đang đăng nhập.")
            return
        if ask_yes_no(dlg, "Xóa người dùng", f"Xóa tài khoản {name}? Các khóa của người này vẫn được giữ lại."):
            UserStore.delete(name)
            refresh()

    row = ttk.Frame(body, style="Card.TFrame")
    row.pack(fill="x", pady=(10, 0))
    ttk.Button(row, text="Đổi quyền", style="Ghost.TButton", command=do_role).pack(side="left", padx=(0, 6))
    ttk.Button(row, text="Xóa", style="Ghost.TButton", command=do_delete).pack(side="left")
    ttk.Button(row, text="Đóng", style="Ghost.TButton", command=dlg.destroy).pack(side="right")
    dlg.bind("<Escape>", lambda e: dlg.destroy())
    refresh()
    _center_on_parent(dlg, parent)
    parent.wait_window(dlg)


def _enable_dpi_awareness() -> None:
    """Windows: bật DPI-aware để chữ sắc nét (không bị nhòe khi màn hình phóng to 125-150%)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def run_gui(tool: FalconPDFTool):
    """Đăng nhập -> cửa sổ chính; "Đăng xuất" quay lại màn hình đăng nhập."""
    _enable_dpi_awareness()
    while True:
        user = _login_window()
        if not user or _main_window(tool, user) != "logout":
            return


def _main_window(tool: FalconPDFTool, user: Dict[str, Any]) -> str:
    me = user["username"]
    is_admin = user.get("role") == "admin"
    outcome = {"v": "quit"}
    root = tk.Tk()
    root.title(f"Falcon PDF Tool {APP_VERSION} - {user.get('fullname') or me}")
    # Kích thước cửa sổ theo DPI thực, không vượt quá màn hình
    scale = root.winfo_fpixels("1i") / 96.0
    w = min(int(1000 * scale), root.winfo_screenwidth() - 40)
    h = min(int(980 * scale), root.winfo_screenheight() - 80)
    root.geometry(f"{w}x{h}")
    root.minsize(min(int(900 * scale), w), min(int(760 * scale), h))
    _setup_styles(root)

    status_var = tk.StringVar(value="Sẵn sàng")
    msg_queue: "queue.Queue[Tuple[str, str, str]]" = queue.Queue()

    # Luồng giao diện đọc kết quả từ queue (Mục 2.3.1 - threading.Thread + queue.Queue)
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
                elif msg_type == "result":
                    set_result(title, content)
                    continue
                status_var.set("Sẵn sàng")
        except queue.Empty:
            pass
        root.after(100, check_queue)

    # ---------- Header ----------
    header = ttk.Frame(root, style="Header.TFrame", padding=(22, 14))
    header.pack(fill="x")
    brand = ttk.Frame(header, style="Header.TFrame")
    brand.pack(side="left")
    ttk.Label(brand, text="Falcon PDF Tool", style="Header.TLabel").pack(anchor="w")
    ttk.Label(brand, text="Ký số & xác thực tài liệu PDF bằng chữ ký hậu lượng tử Falcon (NIST FIPS 206)",
              style="HeaderSub.TLabel").pack(anchor="w")

    # Người dùng đang đăng nhập + Quản lý người dùng (admin) + Đăng xuất
    def do_logout():
        if ask_yes_no(root, "Đăng xuất", "Bạn có muốn đăng xuất không?"):
            outcome["v"] = "logout"
            root.destroy()

    account = ttk.Frame(header, style="Header.TFrame")
    account.pack(side="right")
    ttk.Button(account, text="Đăng xuất", style="Ghost.TButton", command=do_logout).pack(side="right", padx=(8, 0))
    if is_admin:
        ttk.Button(account, text="Người dùng", style="Ghost.TButton",
                   command=lambda: _users_dialog(root, me)).pack(side="right", padx=(8, 0))
    who = ttk.Frame(account, style="Header.TFrame")
    who.pack(side="right", padx=(0, 6))
    ttk.Label(who, text=f"👤 {user.get('fullname') or me}", style="HeaderUser.TLabel").pack(anchor="e")
    ttk.Label(who, text=f"@{me} · {'Quản trị viên' if is_admin else 'Người dùng'}",
              style="HeaderRole.TLabel").pack(anchor="e")
    tk.Frame(root, bg=Theme.ACCENT, height=4).pack(fill="x")

    # ---------- Footer (đặt trước để luôn nằm đáy) ----------
    _build_footer(root)

    content = ttk.Frame(root, padding=(16, 12))
    content.pack(fill="both", expand=True)

    def card(parent, title: str, subtitle: str):
        outer = tk.Frame(parent, bg=Theme.BORDER)
        outer.pack(fill="x", pady=5)
        inner = ttk.Frame(outer, style="Card.TFrame", padding=(18, 12))
        inner.pack(fill="both", padx=1, pady=1)
        ttk.Label(inner, text=title, style="CardTitle.TLabel").grid(row=0, column=0, columnspan=5, sticky="w")
        ttk.Label(inner, text=subtitle, style="Muted.TLabel").grid(row=1, column=0, columnspan=5, sticky="w", pady=(0, 10))
        inner.columnconfigure(1, weight=1)
        return inner

    # ---------- 1. Key Manager ----------
    f1 = card(content, "1. Quản lý khóa", "Sinh cặp khóa Falcon - lưu tại keys/<người dùng>/public/keyN.hex và private/privateN.fpk")
    ttk.Label(f1, text="Người dùng:", style="Card.TLabel").grid(row=2, column=0, sticky="w")
    ttk.Label(f1, text=me, style="CardTitle.TLabel").grid(row=2, column=1, sticky="w", padx=6)
    ttk.Label(f1, text="Thuật toán:", style="Card.TLabel").grid(row=2, column=2, sticky="e")
    algo_var = tk.StringVar(value="falcon_512")
    ttk.Combobox(f1, textvariable=algo_var, values=["falcon_512", "falcon_1024"], state="readonly",
                 width=14, font=Theme.INPUT).grid(row=2, column=3, padx=6)

    def do_keygen():
        # Không cần mật khẩu: chỉ xác nhận "Có" / "Không"
        if not ask_yes_no(root, "Xác nhận sinh khóa", "Bạn có chắc chắn muốn sinh khóa không?"):
            status_var.set("Đã hủy thao tác sinh khóa.")
            return
        owner = me

        def task():
            try:
                status_var.set("Đang sinh cặp khóa Falcon (NTRU + FFT Tree)...")
                tool.algorithm = algo_var.get()
                tool.engine = FalconEngine(tool.algorithm)
                res = tool.keygen(owner=owner)
                msg_queue.put(("result", "ok",
                               f"✔ ĐÃ SINH CẶP KHÓA #{res['index']} ({res['algorithm']})\n"
                               f"Sinh khóa trong: {res['keygen_time_ms']} ms\n"
                               f"Khóa công khai: {res['public_path']}\n"
                               f"Khóa bí mật:   {res['private_path']}"))
                msg_queue.put(
                    ("info", "Thành công",
                     f"Đã sinh cặp khóa #{res['index']} ({res['algorithm']})\n\n"
                     f"Khóa công khai: {res['public_path']}\n"
                     f"Khóa bí mật:   {res['private_path']}")
                )
            except Exception as e:
                msg_queue.put(("error", "Lỗi Sinh Khóa", str(e)))
        threading.Thread(target=task, daemon=True).start()

    ttk.Button(f1, text="Sinh khóa", style="Accent.TButton", command=do_keygen).grid(row=2, column=4, sticky="e")

    # ---------- 2. Sign PDF ----------
    f2 = card(content, "2. Ký số tài liệu", "Chọn PDF gốc, khóa bí mật (.fpk) và nơi lưu tệp đã ký")
    pdf_var, key_var, out_var = tk.StringVar(), tk.StringVar(), tk.StringVar()

    def pick_key():
        pub_dir, priv_dir = KeyStore.user_dirs(me)
        path = filedialog.askopenfilename(initialdir=str(priv_dir) if priv_dir.is_dir() else str(KEYS_ROOT),
                                          filetypes=[("Falcon private key", "*.fpk")])
        if path:
            key_var.set(path)

    def pick_pdf():
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if path:
            pdf_var.set(path)
            if not out_var.get():
                p = Path(path)
                out_var.set(str(p.with_name(p.stem + "_signed.pdf")))

    rows = [
        ("PDF gốc:", pdf_var, pick_pdf),
        ("Khóa (.fpk):", key_var, pick_key),
        ("PDF xuất:", out_var, lambda: out_var.set(
            filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")]) or out_var.get())),
    ]
    for i, (label, var, cmd) in enumerate(rows, start=2):
        ttk.Label(f2, text=label, style="Card.TLabel").grid(row=i, column=0, sticky="w", pady=3)
        ttk.Entry(f2, textvariable=var, font=Theme.INPUT).grid(row=i, column=1, columnspan=2, sticky="ew", padx=6, pady=3)
        ttk.Button(f2, text="Chọn…", style="Ghost.TButton", command=cmd).grid(row=i, column=3, sticky="ew", pady=3)

    def do_sign():
        if not pdf_var.get() or not key_var.get() or not out_var.get():
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn đầy đủ tệp PDF gốc, Khóa và Đường dẫn xuất!")
            return
        # Xác nhận trước khi ký: "Có" -> ký, "Không" -> bỏ qua
        if not ask_yes_no(root, "Xác nhận ký số", "Bạn có chắc chắn muốn ký hay không?"):
            status_var.set("Đã hủy thao tác ký.")
            return
        pwd = ""
        if KeyStore.key_is_protected(key_var.get()):
            # Chỉ khóa cũ (sinh trước v3.1) mới có mật khẩu
            pwd = PasswordManager.ask_password(root, title="Nhập mật khẩu khóa để ký số", confirm=False)
            if pwd is None:
                return

        # Kiểm tra khóa NGAY trên luồng giao diện — lỗi (sai mật khẩu, khóa hỏng) thì chặn, không ký
        try:
            KeyStore.load_keypair(Path(key_var.get()), pwd)
        except Exception as e:
            messagebox.showerror("Không mở được khóa", f"{e}\n\nKhông thể thực hiện ký số.")
            status_var.set("Sẵn sàng")
            return

        signer = me

        def task():
            try:
                status_var.set("Đang ký số Falcon...")
                res = tool.sign_pdf(pdf_var.get(), key_var.get(), out_var.get(), password=pwd, signer=signer)
                msg_queue.put(("result", "ok",
                               f"✔ ĐÃ KÝ THÀNH CÔNG\n"
                               f"Thuật toán: {res['algorithm']}   •   Chữ ký: {res['sig_bytes_len']} bytes\n"
                               f"Ký trong: {res['sign_time_ms']} ms\n"
                               f"Tệp xuất: {res['output_pdf']}"))
                msg_queue.put(("info", "Thành công",
                               f"Đã ký thành công!\nThuật toán: {res['algorithm']}\n"
                               f"Kích thước chữ ký: {res['sig_bytes_len']} bytes\n"
                               f"Ký trong: {res['sign_time_ms']} ms"))
            except Exception as e:
                msg_queue.put(("error", "Lỗi Ký Số", str(e)))
        threading.Thread(target=task, daemon=True).start()

    ttk.Button(f2, text="Thực hiện ký số", style="Accent.TButton", command=do_sign).grid(row=5, column=3, sticky="e", pady=(8, 0))

    # ---------- 3. Verify & Inspector ----------
    f3 = card(content, "3. Xác thực & Trích xuất", "Kiểm tra chữ ký Falcon, tính toàn vẹn và xem siêu dữ liệu")
    vpdf_var = tk.StringVar()
    ttk.Label(f3, text="Tệp PDF:", style="Card.TLabel").grid(row=2, column=0, sticky="w")
    ttk.Entry(f3, textvariable=vpdf_var, font=Theme.INPUT).grid(row=2, column=1, columnspan=2, sticky="ew", padx=6)
    ttk.Button(f3, text="Chọn…", style="Ghost.TButton",
               command=lambda: vpdf_var.set(filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")]) or vpdf_var.get())
               ).grid(row=2, column=3, sticky="ew")

    def do_verify():
        if not vpdf_var.get():
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tệp PDF để xác thực!")
            return

        def task():
            try:
                status_var.set("Đang xác thực chữ ký Falcon và kiểm tra tính toàn vẹn...")
                res = tool.verify_pdf(vpdf_var.get())
                sign_ms = res.get("sign_time_ms")
                head = "✔ CHỮ KÝ HỢP LỆ (VALID)" if res.get("valid") else f"✘ CHỮ KÝ KHÔNG HỢP LỆ (INVALID)\n{res.get('error', '')}"
                text = (f"{head}\n"
                        f"Ký trong: {sign_ms if sign_ms is not None else 'N/A'} ms   •   "
                        f"Xác thực trong: {res.get('verify_time_ms')} ms\n"
                        f"Người ký: {res.get('signer') or 'N/A'}   •   Thuật toán: {res.get('algorithm')}\n"
                        f"Ngày ký: {res.get('sign_date')}   •   PQC: {res.get('pqc_status')}\n"
                        f"Fingerprint: {res.get('pk_fingerprint')}")
                msg_queue.put(("result", "ok" if res.get("valid") else "err", text))
                status_var.set("Sẵn sàng")
            except Exception as e:
                msg_queue.put(("error", "Lỗi Xác Thực", str(e)))
        threading.Thread(target=task, daemon=True).start()

    def do_extract():
        if not vpdf_var.get():
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tệp PDF để trích xuất!")
            return
        try:
            data = tool.extract_text_and_properties(vpdf_var.get())
            props_str = "\n".join([f" - {k}: {v}" for k, v in data["properties"].items()])
            info_text = (f"Tổng số trang: {data['total_pages']}\n\nSIÊU DỮ LIỆU (PROPERTIES):\n{props_str}\n\n"
                         f"NỘI DUNG VĂN BẢN (500 ký tự đầu):\n{data['text'][:500]}...")
            set_result("info", info_text)
        except Exception as e:
            messagebox.showerror("Lỗi Trích Xuất", str(e))

    btns = ttk.Frame(f3, style="Card.TFrame")
    btns.grid(row=3, column=0, columnspan=4, sticky="e", pady=(8, 0))
    ttk.Button(btns, text="Trích xuất Properties", style="Ghost.TButton", command=do_extract).pack(side="right", padx=(6, 0))
    ttk.Button(btns, text="Xác thực chữ ký", style="Accent.TButton", command=do_verify).pack(side="right")

    # ---------- Kết quả ----------
    res_outer = tk.Frame(content, bg=Theme.BORDER)
    res_outer.pack(fill="both", expand=True, pady=6)
    result_box = tk.Text(res_outer, height=7, wrap="word", relief="flat", bg=Theme.CARD, fg=Theme.TEXT,
                         font=Theme.MONO, padx=14, pady=10)
    result_box.pack(fill="both", expand=True, padx=1, pady=1)
    result_box.tag_configure("ok", foreground=Theme.OK, font=(Theme.MONO[0], Theme.MONO[1], "bold"))
    result_box.tag_configure("err", foreground=Theme.ERR, font=(Theme.MONO[0], Theme.MONO[1], "bold"))
    result_box.insert("1.0", "Kết quả ký / xác thực sẽ hiển thị tại đây.")
    result_box.configure(state="disabled")

    def set_result(kind: str, text: str):
        result_box.configure(state="normal")
        result_box.delete("1.0", "end")
        result_box.insert("1.0", text)
        if kind in ("ok", "err"):
            result_box.tag_add(kind, "1.0", "1.end")
        result_box.configure(state="disabled")

    root.after(100, check_queue)
    root.mainloop()
    return outcome["v"]


if __name__ == "__main__":
    tool = FalconPDFTool()
    run_gui(tool)
