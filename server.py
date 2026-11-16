#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
FALCON PDF SERVER - Máy chủ web đa người dùng cho công cụ ký số PDF Falcon
Đồ án: Nghiên cứu tích hợp công cụ trích xuất và ký tài liệu PDF bảo mật
       sử dụng ký số hậu lượng tử Falcon - Lê Hải Anh - DT060102
================================================================================

Vai trò trong kiến trúc 4 tầng (Mục 2.3.1, Hình 2.3):
  Đây là phần mở rộng của TẦNG 1 (Giao diện & Điều hành) qua giao thức HTTP,
  cho phép nhiều người dùng truy cập đồng thời bằng trình duyệt. Các tầng 2-4
  (PyPDF, Falcon Engine, KeyStore) được tái sử dụng nguyên vẹn từ
  falcon_pdf_tool.py.

Chức năng:
  - Đăng ký / đăng nhập, phân quyền admin / user (người đăng ký đầu tiên là admin)
  - Mỗi người dùng có kho khóa riêng: keys/<user>/public/keyN.hex,
    keys/<user>/private/privateN.fpk
  - Tải lên PDF, ký số (xác nhận "Có/Không" + mật khẩu), xác thực, trích xuất
  - Gửi tài liệu cho người dùng khác, hộp thư "Tài liệu nhận được"
  - Xác định người ký bằng cách đối chiếu fingerprint khóa công khai với kho khóa

Chạy:  python server.py  [--host 0.0.0.0] [--port 5000]
Truy cập: http://<IP-máy-chủ>:5000
================================================================================
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import secrets
import socket
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request,
    send_file, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from falcon_pdf_tool import (
    APP_DIR, APP_VERSION, AUTHOR_ADDRESS, AUTHOR_EMAIL, KEYS_ROOT,
    FalconEngine, FalconPDFTool, KeyInspector, KeyStore, safe_name,
)

BASE_DIR = APP_DIR  # thư mục dữ liệu thật (đúng cả khi đóng gói .exe)
DATA_DIR = BASE_DIR / "server_data"
FILES_DIR = DATA_DIR / "files"
USERS_FILE = DATA_DIR / "users.json"
DOCS_FILE = DATA_DIR / "documents.json"
SECRET_FILE = DATA_DIR / "secret.key"

ALGORITHMS = ["falcon_512", "falcon_1024"]
MAX_UPLOAD_MB = 30

DATA_DIR.mkdir(parents=True, exist_ok=True)
FILES_DIR.mkdir(parents=True, exist_ok=True)
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")

app = Flask(__name__)
app.secret_key = SECRET_FILE.read_text(encoding="utf-8").strip()
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
# Sửa tệp trong templates/ là có hiệu lực ngay, không cần khởi động lại server
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Một khóa cho mọi thao tác đọc/ghi tệp JSON - nhiều người dùng truy cập đồng thời
_db_lock = threading.RLock()


# ------------------------------------------------------------------------------
#   Lưu trữ JSON
# ------------------------------------------------------------------------------

def _load(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save(path: Path, data) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def load_users() -> Dict[str, Dict[str, Any]]:
    return _load(USERS_FILE, {})


def load_docs() -> Dict[str, Dict[str, Any]]:
    return _load(DOCS_FILE, {})


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def doc_path(doc_id: str) -> Path:
    return FILES_DIR / f"{doc_id}.pdf"


def add_document(owner: str, name: str, data: bytes, kind: str, **extra) -> Dict[str, Any]:
    doc_id = secrets.token_hex(8)
    doc_path(doc_id).write_bytes(data)
    doc = {
        "id": doc_id,
        "name": name,
        "owner": owner,
        "kind": kind,            # "uploaded" | "signed"
        "size": len(data),
        "created": now_str(),
        "shared_with": [],
        "messages": [],
    }
    doc.update(extra)
    with _db_lock:
        docs = load_docs()
        docs[doc_id] = doc
        _save(DOCS_FILE, docs)
    return doc


def can_access(doc: Dict[str, Any], user: Dict[str, Any]) -> bool:
    return (doc["owner"] == user["username"]
            or user["username"] in doc.get("shared_with", [])
            or user.get("role") == "admin")


def get_doc_or_404(doc_id: str) -> Dict[str, Any]:
    doc = load_docs().get(doc_id)
    if not doc or not doc_path(doc_id).is_file() or not can_access(doc, g.user):
        abort(404)
    return doc


def find_key_owner(fingerprint: str) -> Optional[Dict[str, Any]]:
    """Đối chiếu fingerprint khóa công khai trong PDF với kho khóa của mọi người dùng."""
    if not fingerprint:
        return None
    users = load_users()
    for username in users:
        for k in KeyStore.list_keys(username):
            if k["fingerprint"] == fingerprint:
                return {"username": username, "fullname": users[username].get("fullname", ""),
                        "key": k["name"], "algorithm": k["algorithm"]}
    return None


# ------------------------------------------------------------------------------
#   Phiên đăng nhập, phân quyền, CSRF
# ------------------------------------------------------------------------------

@app.before_request
def load_current_user():
    g.user = None
    username = session.get("user")
    if username:
        user = load_users().get(username)
        if user:
            g.user = dict(user, username=username)
        else:
            session.clear()
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        token = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
        if not token or not secrets.compare_digest(token, session["csrf"]):
            abort(400, "CSRF token không hợp lệ - hãy tải lại trang.")


@app.context_processor
def inject_globals():
    return {
        "current_user": g.get("user"),
        "csrf_token": session.get("csrf", ""),
        "app_version": APP_VERSION,
        "author_email": AUTHOR_EMAIL,
        "author_address": AUTHOR_ADDRESS,
        "algorithms": ALGORITHMS,
    }


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.template_filter("filesize")
def filesize(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ------------------------------------------------------------------------------
#   Xác thực người dùng
# ------------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        fullname = request.form.get("fullname", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        error = None
        if not username or safe_name(username) != username or len(username) < 3:
            error = "Tên đăng nhập tối thiểu 3 ký tự, chỉ gồm chữ không dấu, số, dấu _ . -"
        elif len(password) < 6:
            error = "Mật khẩu tối thiểu 6 ký tự."
        elif password != password2:
            error = "Hai lần nhập mật khẩu không khớp."
        if not error:
            with _db_lock:
                users = load_users()
                if username.lower() in (u.lower() for u in users):
                    error = "Tên đăng nhập đã tồn tại."
                else:
                    users[username] = {
                        "fullname": fullname or username,
                        "password_hash": generate_password_hash(password),
                        "role": "admin" if not users else "user",
                        "created": now_str(),
                    }
                    _save(USERS_FILE, users)
        if error:
            flash(error, "error")
        else:
            session.clear()
            session["user"] = username
            flash("Tạo tài khoản thành công. Hãy sinh cặp khóa Falcon đầu tiên.", "success")
            return redirect(url_for("keys"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = load_users().get(username)
        if user and check_password_hash(user["password_hash"], password):
            nxt = request.args.get("next") or url_for("dashboard")
            if not nxt.startswith("/"):
                nxt = url_for("dashboard")
            session.clear()
            session["user"] = username
            return redirect(nxt)
        flash("Sai tên đăng nhập hoặc mật khẩu.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------------------
#   Tổng quan
# ------------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    me = g.user["username"]
    docs = load_docs().values()
    mine = [d for d in docs if d["owner"] == me]
    received = [d for d in docs if me in d.get("shared_with", [])]
    recent = sorted(mine + received, key=lambda d: d["created"], reverse=True)[:6]
    return render_template(
        "dashboard.html",
        key_count=len(KeyStore.list_keys(me)),
        doc_count=len(mine),
        signed_count=sum(1 for d in mine if d["kind"] == "signed"),
        received_count=len(received),
        recent=recent,
    )


# ------------------------------------------------------------------------------
#   Quản lý khóa  (Mục 3.3 "Quy trình sinh khóa")
# ------------------------------------------------------------------------------

@app.route("/keys")
@login_required
def keys():
    return render_template("keys.html", keys=KeyStore.list_keys(g.user["username"]))


@app.route("/keys/generate", methods=["POST"])
@login_required
def keys_generate():
    # Không cần mật khẩu khóa - người dùng đã xác nhận "Có" trên trình duyệt
    algo = request.form.get("algorithm", "falcon_512")
    if algo not in ALGORITHMS:
        flash("Thuật toán không hợp lệ.", "error")
    else:
        tool = FalconPDFTool(algo)
        with _db_lock:  # tránh 2 yêu cầu cùng lúc lấy trùng số thứ tự keyN
            res = tool.keygen(owner=g.user["username"])
        flash(f"Đã tạo khóa key{res['index']} ({algo}) trong {res['keygen_time_ms']} ms.", "success")
    return redirect(url_for("keys"))


@app.route("/keys/inspect", methods=["GET", "POST"])
@login_required
def keys_inspect():
    """Kiểm tra thuộc tính khóa: khóa của tôi, tệp tải lên (.hex / .fpk) hoặc chuỗi hex dán vào."""
    me = g.user["username"]
    my_keys = KeyStore.list_keys(me)
    source = request.values.get("source", "mine")
    selected = request.values.get("key", "")
    result, error, label = None, "", ""
    if request.method == "POST":
        password = request.form.get("password", "")
        try:
            if source == "mine":
                path = _user_key_path(me, int(selected or 0), public=False)
                if not path.is_file():
                    raise ValueError("Không tìm thấy khóa đã chọn.")
                label = f"key{selected} · {path.name}"
                result = KeyInspector.inspect_private(json.loads(path.read_text(encoding="utf-8")), password)
            elif source == "file":
                f = request.files.get("keyfile")
                if not f or not f.filename:
                    raise ValueError("Hãy chọn tệp khóa (.hex hoặc .fpk).")
                data = f.read(1024 * 1024)
                label = Path(f.filename).name
                text = data.decode("utf-8", errors="ignore").strip()
                if text.startswith("{"):
                    result = KeyInspector.inspect_private(json.loads(text), password)
                else:
                    hex_text = re.sub(r"\s+", "", text)
                    is_hex = re.fullmatch(r"[0-9a-fA-F]+", hex_text) and len(hex_text) % 2 == 0
                    pk = bytes.fromhex(hex_text) if is_hex else data
                    result = KeyInspector.inspect_public(pk)
            else:
                hex_text = re.sub(r"\s+", "", request.form.get("pk_hex", ""))
                if not hex_text:
                    raise ValueError("Hãy dán khóa công khai dạng hex.")
                if not re.fullmatch(r"[0-9a-fA-F]+", hex_text):
                    raise ValueError("Chuỗi hex không hợp lệ.")
                label = "Khóa công khai (hex)"
                result = KeyInspector.inspect_public(bytes.fromhex(hex_text))
        except (ValueError, json.JSONDecodeError) as e:
            error = str(e) if str(e) else "Dữ liệu khóa không hợp lệ."
        if result is not None:
            result["owner"] = find_key_owner(result["fingerprint"])
            statuses = {c["status"] for c in result["checks"]}
            result["valid"] = "bad" not in statuses
            # Hợp lệ nhưng phần khóa bí mật chưa được kiểm tra (chưa nhập / sai mật khẩu)
            result["partial"] = result["valid"] and bool(statuses & {"skip", "warn"})
            result["label"] = label
    return render_template("keys_inspect.html", keys=my_keys, source=source, selected=selected,
                           result=result, error=error)


def _user_key_path(username: str, index: int, public: bool) -> Path:
    pub_dir, priv_dir = KeyStore.user_dirs(username)
    return pub_dir / f"key{index}.hex" if public else priv_dir / f"private{index}.fpk"


@app.route("/keys/<int:index>/download/<kind>")
@login_required
def keys_download(index: int, kind: str):
    if kind not in ("public", "private"):
        abort(404)
    path = _user_key_path(g.user["username"], index, kind == "public")
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route("/keys/<int:index>/delete", methods=["POST"])
@login_required
def keys_delete(index: int):
    for public in (True, False):
        p = _user_key_path(g.user["username"], index, public)
        if p.is_file():
            p.unlink()
    flash(f"Đã xóa cặp khóa key{index}.", "success")
    return redirect(url_for("keys"))


# ------------------------------------------------------------------------------
#   Tài liệu: tải lên, tải xuống, gửi, xóa, trích xuất
# ------------------------------------------------------------------------------

def _read_pdf_upload(field: str = "file") -> Optional[tuple]:
    f = request.files.get(field)
    if not f or not f.filename:
        return None
    data = f.read()
    if not data.startswith(b"%PDF"):
        raise ValueError("Tệp tải lên không phải PDF hợp lệ.")
    name = Path(f.filename).name or "document.pdf"
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    return name, data


@app.route("/documents")
@login_required
def documents():
    me = g.user["username"]
    docs = load_docs().values()
    mine = sorted([d for d in docs if d["owner"] == me], key=lambda d: d["created"], reverse=True)
    received = sorted([d for d in docs if me in d.get("shared_with", [])], key=lambda d: d["created"], reverse=True)
    others = sorted(u for u in load_users() if u != me)
    return render_template("documents.html", mine=mine, received=received, users=others)


@app.route("/documents/upload", methods=["POST"])
@login_required
def documents_upload():
    try:
        up = _read_pdf_upload()
        if not up:
            flash("Hãy chọn tệp PDF.", "error")
        else:
            add_document(g.user["username"], up[0], up[1], "uploaded")
            flash(f"Đã tải lên {up[0]}.", "success")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("documents"))


@app.route("/documents/<doc_id>/download")
@login_required
def documents_download(doc_id: str):
    doc = get_doc_or_404(doc_id)
    return send_file(doc_path(doc_id), as_attachment=True, download_name=doc["name"],
                     mimetype="application/pdf")


@app.route("/documents/<doc_id>/view")
@login_required
def documents_view(doc_id: str):
    doc = get_doc_or_404(doc_id)
    return send_file(doc_path(doc_id), download_name=doc["name"], mimetype="application/pdf")


@app.route("/documents/<doc_id>/send", methods=["POST"])
@login_required
def documents_send(doc_id: str):
    # Gọi từ hộp thoại Gửi bằng fetch() -> trả JSON; form thường -> chuyển trang
    wants_json = request.headers.get("X-Requested-With") == "fetch"
    recipient = request.form.get("recipient", "").strip()
    note = request.form.get("note", "").strip()[:500]
    with _db_lock:
        docs = load_docs()
        doc = docs.get(doc_id)
        if not doc or doc["owner"] != g.user["username"]:
            abort(404)
        if recipient not in load_users() or recipient == g.user["username"]:
            if wants_json:
                return jsonify(ok=False, error="Người nhận không hợp lệ."), 400
            flash("Người nhận không hợp lệ.", "error")
            return redirect(url_for("documents"))
        if recipient not in doc["shared_with"]:
            doc["shared_with"].append(recipient)
        sent_at = now_str()
        doc.setdefault("messages", []).append(
            {"from": g.user["username"], "to": recipient, "note": note, "time": sent_at})
        _save(DOCS_FILE, docs)
    if wants_json:
        return jsonify(ok=True, name=doc["name"], recipient=recipient, time=sent_at)
    flash(f"Đã gửi '{doc['name']}' tới {recipient}.", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<doc_id>/delete", methods=["POST"])
@login_required
def documents_delete(doc_id: str):
    with _db_lock:
        docs = load_docs()
        doc = docs.get(doc_id)
        if not doc:
            abort(404)
        me = g.user["username"]
        if doc["owner"] == me or g.user.get("role") == "admin":
            docs.pop(doc_id)
            if doc_path(doc_id).is_file():
                doc_path(doc_id).unlink()
            flash(f"Đã xóa '{doc['name']}'.", "success")
        elif me in doc.get("shared_with", []):
            doc["shared_with"].remove(me)  # người nhận chỉ gỡ khỏi hộp thư của mình
            flash(f"Đã gỡ '{doc['name']}' khỏi hộp thư.", "success")
        else:
            abort(404)
        _save(DOCS_FILE, docs)
    return redirect(url_for("documents"))


@app.route("/documents/<doc_id>/extract")
@login_required
def documents_extract(doc_id: str):
    doc = get_doc_or_404(doc_id)
    try:
        data = FalconPDFTool().extract_text_and_properties(str(doc_path(doc_id)))
    except Exception as e:
        flash(f"Lỗi trích xuất: {e}", "error")
        return redirect(url_for("documents"))
    return render_template("extract.html", doc=doc, data=data)


# ------------------------------------------------------------------------------
#   Ký số  (Mục 2.2.2.a, 3.3 "Quy trình ký số")
# ------------------------------------------------------------------------------

@app.route("/sign")
@login_required
def sign():
    me = g.user["username"]
    docs = [d for d in load_docs().values() if can_access(d, g.user)]
    docs.sort(key=lambda d: d["created"], reverse=True)
    # Chỉ khóa Falcon thật (định dạng v3) mới dùng được để ký
    keys = [k for k in KeyStore.list_keys(me) if not k["legacy"]]
    return render_template("sign.html", keys=keys, docs=docs,
                           preselect=request.args.get("doc", ""))


@app.route("/api/sign", methods=["POST"])
@login_required
def api_sign():
    """Được gọi từ trình duyệt SAU khi người dùng chọn "Có" (khóa cũ có mật khẩu: kèm mật khẩu)."""
    me = g.user["username"]
    try:
        key_index = int(request.form.get("key_index", "0"))
    except ValueError:
        key_index = 0
    password = request.form.get("password", "")
    reason = (request.form.get("reason", "").strip() or "Ky so PDF Falcon")[:200]

    key_path = _user_key_path(me, key_index, public=False)
    if not key_path.is_file():
        return jsonify(ok=False, error="Không tìm thấy khóa bí mật đã chọn."), 400

    # Nguồn PDF: tệp tải lên mới hoặc tài liệu có sẵn trên máy chủ
    try:
        up = _read_pdf_upload()
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    src_doc = None
    if up:
        src_name, src_bytes = up
    else:
        src_doc = load_docs().get(request.form.get("doc_id", ""))
        if not src_doc or not can_access(src_doc, g.user):
            return jsonify(ok=False, error="Hãy chọn tài liệu hoặc tải lên tệp PDF."), 400
        src_name = src_doc["name"]

    out_name = Path(src_name).stem + "_signed.pdf"
    with tempfile.TemporaryDirectory() as tmp:
        out_tmp = Path(tmp) / "out.pdf"
        if up:
            src_path = Path(tmp) / "in.pdf"
            src_path.write_bytes(src_bytes)
        else:
            src_path = doc_path(src_doc["id"])
        try:
            res = FalconPDFTool().sign_pdf(str(src_path), str(key_path), str(out_tmp),
                                           password=password, reason=reason, signer=me)
        except ValueError as e:
            return jsonify(ok=False, error=str(e)), 400
        except Exception as e:
            return jsonify(ok=False, error=f"Lỗi ký số: {e}"), 500
        signed_bytes = out_tmp.read_bytes()

    if up:  # chỉ lưu tệp gốc khi ký thành công
        src_doc = add_document(me, src_name, src_bytes, "uploaded")
    new_doc = add_document(
        me, out_name, signed_bytes, "signed",
        signed_from=src_doc["id"],
        sign_info={"algorithm": res["algorithm"], "sign_time_ms": res["sign_time_ms"],
                   "sig_len": res["sig_bytes_len"], "key": f"key{key_index}",
                   "fingerprint": res["pk_fingerprint"], "reason": reason},
    )
    return jsonify(
        ok=True,
        doc_id=new_doc["id"],
        name=out_name,
        algorithm=res["algorithm"],
        sig_len=res["sig_bytes_len"],
        sign_time_ms=res["sign_time_ms"],
        key=f"key{key_index}",
        fingerprint=res["pk_fingerprint"][:16],
        download_url=url_for("documents_download", doc_id=new_doc["id"]),
        verify_url=url_for("verify_document", doc_id=new_doc["id"]),
    )


# ------------------------------------------------------------------------------
#   Xác thực  (Mục 2.2.2.b, 3.3 "Quy trình xác thực")
# ------------------------------------------------------------------------------

def _verify_bytes_path(path: Path) -> Dict[str, Any]:
    res = FalconPDFTool().verify_pdf(str(path))
    res["registered_owner"] = find_key_owner(res.get("pk_fingerprint_full", ""))
    return res


@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    result, name = None, None
    if request.method == "POST":
        try:
            up = _read_pdf_upload()
            if not up:
                flash("Hãy chọn tệp PDF cần xác thực.", "error")
            else:
                name = up[0]
                with tempfile.TemporaryDirectory() as tmp:
                    p = Path(tmp) / "v.pdf"
                    p.write_bytes(up[1])
                    result = _verify_bytes_path(p)
        except ValueError as e:
            flash(str(e), "error")
    return render_template("verify.html", result=result, name=name)


@app.route("/documents/<doc_id>/verify")
@login_required
def verify_document(doc_id: str):
    doc = get_doc_or_404(doc_id)
    result = _verify_bytes_path(doc_path(doc_id))
    return render_template("verify.html", result=result, name=doc["name"], doc=doc)


# ------------------------------------------------------------------------------
#   Quản trị người dùng
# ------------------------------------------------------------------------------

@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    docs = load_docs().values()
    rows = []
    for name, u in sorted(users.items()):
        rows.append({
            "username": name, "fullname": u.get("fullname", ""), "role": u.get("role", "user"),
            "created": u.get("created", ""), "keys": len(KeyStore.list_keys(name)),
            "docs": sum(1 for d in docs if d["owner"] == name),
        })
    return render_template("admin.html", rows=rows)


@app.route("/admin/users/<username>/role", methods=["POST"])
@admin_required
def admin_set_role(username: str):
    role = request.form.get("role")
    with _db_lock:
        users = load_users()
        if username not in users or role not in ("admin", "user"):
            abort(404)
        if username == g.user["username"] and role != "admin":
            flash("Không thể tự hạ quyền quản trị của chính mình.", "error")
        else:
            users[username]["role"] = role
            _save(USERS_FILE, users)
            flash(f"Đã đặt quyền '{role}' cho {username}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def admin_delete_user(username: str):
    if username == g.user["username"]:
        flash("Không thể xóa tài khoản đang đăng nhập.", "error")
        return redirect(url_for("admin_users"))
    with _db_lock:
        users = load_users()
        if users.pop(username, None) is None:
            abort(404)
        _save(USERS_FILE, users)
    flash(f"Đã xóa tài khoản {username} (khóa và tài liệu vẫn được giữ lại trên máy chủ).", "success")
    return redirect(url_for("admin_users"))


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(400)
@app.errorhandler(413)
def http_error(e):
    code = getattr(e, "code", 500)
    msg = {403: "Bạn không có quyền truy cập trang này.",
           404: "Không tìm thấy tài nguyên.",
           413: f"Tệp quá lớn (tối đa {MAX_UPLOAD_MB} MB)."}.get(code, getattr(e, "description", "Lỗi yêu cầu."))
    if request.path.startswith("/api/"):
        return jsonify(ok=False, error=msg), code
    return render_template("error.html", code=code, message=msg), code


def _lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Falcon PDF Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    print("=" * 64)
    print(f" Falcon PDF Server {APP_VERSION}")
    print(f" Máy này:        http://127.0.0.1:{args.port}")
    print(f" Mạng nội bộ:    http://{_lan_ip()}:{args.port}")
    print(f" Kho khóa:       {KEYS_ROOT}")
    print(f" Dữ liệu:        {DATA_DIR}")
    print("=" * 64)
    app.run(host=args.host, port=args.port, threaded=True, debug=False)
