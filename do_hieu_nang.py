# -*- coding: utf-8 -*-

import sys, time, statistics as st, shutil
from pathlib import Path
from falcon_pdf_tool import FalconPDFTool, KeyStore
from falcon_core import FalconEngine

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

pdf = sys.argv[1] if len(sys.argv) > 1 else "sample.pdf"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 10
root = Path("keys_bench"); shutil.rmtree(root, ignore_errors=True)
fmt = lambda a: f"{st.mean(a):.1f} ({min(a):.1f} – {max(a):.1f})"

for algo in ["falcon_512", "falcon_1024"]:
    tool = FalconPDFTool(algo)
    kg, att = [], []
    for _ in range(N):
        r = tool.keygen(owner="bench", root=root)
        kg.append(r["keygen_time_ms"]); att.append(tool.engine.last_keygen_info["attempts"])
    sg, vf = [], []
    out = f"bench_{algo}.pdf"
    for _ in range(N):
        sg.append(FalconPDFTool(algo).sign_pdf(pdf, r["private_path"], out)["sign_time_ms"])
        v = FalconPDFTool().verify_pdf(out); assert v["valid"]
        vf.append(v["verify_time_ms"])
    print(f"\n=== {algo} ({N} lần) ===")
    print("Sinh khóa (ms):", fmt(kg), "| số lần thử NTRUGen:", min(att), "–", max(att))
    print("Băm + ký (ms): ", fmt(sg))
    print("Xác thực (ms): ", fmt(vf))
    print("Kích thước PDF:", Path(pdf).stat().st_size, "->", Path(out).stat().st_size, "byte")
    # Lõi Falcon
    sk, pk, _ = KeyStore.load_keypair(Path(r["private_path"]))
    e = FalconEngine(algo); FalconEngine._cache.clear()
    t = time.perf_counter(); e.expand_secret_key(sk); tex = (time.perf_counter() - t) * 1000
    m = b"\x00" * 32; ts, tv, retry, norms = [], [], 0, []
    for _ in range(50):
        t = time.perf_counter(); s = e.sign(sk, m); ts.append((time.perf_counter() - t) * 1000)
        retry += e.last_sign_info["attempts"] > 1; norms.append(e.last_sign_info["norm2"])
    for _ in range(50):
        t = time.perf_counter(); e.verify(pk, m, s); tv.append((time.perf_counter() - t) * 1000)
    b2 = e.params["beta2"]
    print(f"Lõi: dựng cây {tex:.1f} ms | ký {st.mean(ts):.1f} ms | xác thực {st.mean(tv):.2f} ms | "
          f"ký lại {retry}/50 | norm² TB {st.mean(norms):.0f} ({st.mean(norms)/b2*100:.1f}% β²)")