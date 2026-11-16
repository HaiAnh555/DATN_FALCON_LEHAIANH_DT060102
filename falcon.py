#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Falcon PDF Tool - prototype for a graduation project.

IMPORTANT:
- Uses the real Falcon implementation from `falcon-python`; it does not implement
  Falcon math itself.
- The PDF signature dictionary uses a project-specific /SubFilter. It can be
  verified by this application, but is NOT a standard Adobe/PAdES signature.
- Install: pip install pypdf falcon-python cryptography
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import re
import secrets
import threading
import time
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

try:
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import (
        ArrayObject, ByteStringObject, DictionaryObject, NameObject,
        NumberObject, TextStringObject,
    )
except ImportError as exc:
    raise SystemExit("Thiếu pypdf. Cài bằng: pip install pypdf") from exc

try:
    from falcon_python import Falcon512, Falcon1024
except ImportError as exc:
    raise SystemExit("Thiếu falcon-python. Cài bằng: pip install falcon-python") from exc

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:
    raise SystemExit("Thiếu cryptography. Cài bằng: pip install cryptography") from exc


ALGORITHMS = {
    "falcon_512": {"class": Falcon512, "max_sig_len": 666, "pk_len": 897, "sk_len": 1281},
    "falcon_1024": {"class": Falcon1024, "max_sig_len": 1280, "pk_len": 1793, "sk_len": 2305},
}
BYTE_RANGE_WIDTH = 12
PDF_MARKER = b"/PQC.SignatureLength"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key(password: str, salt: bytes, iterations: int = 310_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)


class KeyStore:
    """Store secret key encrypted with AES-GCM; public key remains unencrypted."""
    @staticmethod
    def save(path: Path, algorithm: str, public_key: bytes, secret_key: bytes, password: str) -> None:
        if not password:
            raise ValueError("Mật khẩu bảo vệ khóa không được để trống.")
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = derive_key(password, salt)
        aad = f"FalconPDFTool|v2|{algorithm}".encode()
        ciphertext = AESGCM(key).encrypt(nonce, secret_key, aad)
        record = {
            "format": "FalconPDFTool-key-v2",
            "algorithm": algorithm,
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": 310_000,
            "cipher": "AES-256-GCM",
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "secret_key_enc": base64.b64encode(ciphertext).decode("ascii"),
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "public_key_sha256": sha256_hex(public_key),
            "created_utc": utc_now(),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def load(path: Path, password: str) -> tuple[str, bytes, bytes]: