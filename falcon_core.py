#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
FALCON_CORE - CÀI ĐẶT THUẦN PYTHON LƯỢC ĐỒ CHỮ KÝ HẬU LƯỢNG TỬ FALCON (FN-DSA)
Đồ án: Nghiên cứu tích hợp công cụ trích xuất và ký tài liệu PDF bảo mật
       sử dụng ký số hậu lượng tử Falcon - Lê Hải Anh - DT060102
================================================================================

Đây là Tầng 3 "Ký số Hậu lượng tử" (Mục 2.3.1) - cài đặt ĐẦY ĐỦ thuật toán
Falcon theo đặc tả Falcon (NIST PQC Round 3, cơ sở của FIPS 206 / FN-DSA):

  Thành phần                         Đồ án                   Lớp / hàm
  ---------------------------------  ----------------------  ---------------------------
  Tham số chuẩn n, q, σ, σmin, β²    Mục 1.2.1, 3.2.1        FalconNISTParams
  Vành R = Z[x]/(x^n+1), FFT         Mục 1.2.1, 1.2.2.b      FFT
  Nhân đa thức mod q (NTT)           Mục 1.2.1               NTT
  Lấy mẫu Gaussian rời rạc 1 chiều   Mục 1.2.2.b (lá cây)    SamplerZ
  NTRUGen + NTRUSolve (f·G−g·F=q)    Mục 1.2.4.a, 2.2.1.a    NTRUEngine
  Cây LDL (Falcon Tree) + ffSampling Mục 1.2.2.b, 3.2.1      FalconSampler
  Mã hóa pk 14 bit, sk, Compress(s2) Mục 2.2.1.b, 1.2.4.b    FalconEncoding
  HashToPoint, KeyGen, Sign, Verify  Mục 1.2.2.a, 1.2.4      FalconEngine

Quy ước ký hiệu: đặc tả viết chữ ký là (s1, s2) với s1 + s2·h = c (mod q);
đồ án dùng đúng ký hiệu này. Trong mã: s1 <-> `s1`, s2 <-> `s2`.

Toàn bộ khâu xác thực chỉ dùng số nguyên mod q (đúng yêu cầu Mục 1.2.3.a);
khâu sinh khóa và ký dùng số thực dấu phẩy động IEEE-754 binary64 của Python.
Nguồn ngẫu nhiên: thư viện `secrets` (CSPRNG của hệ điều hành - Mục 3.1.2).
================================================================================
"""

from __future__ import annotations

import cmath
import hashlib
import math
import secrets
import threading
from typing import Dict, List, Optional, Tuple

Q = 12289  # Modulo nguyên tố q = 12289 = 3·2^12 + 1 (Mục 1.2.1)


# ==============================================================================
#   THAM SỐ CHUẨN  (Mục 1.2.1, Mục 3.2.1 "Quản lý tham số chuẩn")
# ==============================================================================

class FalconNISTParams:
    """Tham số chuẩn của Falcon-512 và Falcon-1024.

    [Đồ án - Mục 3.2.1]
      - q = 12289
      - Falcon-512 : n = 512,  chữ ký 666 byte,  pk 897 byte,  σ ≈ 165.74, β² = 34034726
      - Falcon-1024: n = 1024, chữ ký 1280 byte, pk 1793 byte, σ ≈ 168.39, β² = 70265242
    [Đồ án - Mục 2.2.1.b] sk 1281 / 2305 byte.
    Các tham số phụ theo đặc tả:
      - sigmin   : σ_min, cận dưới độ lệch chuẩn tại lá của cây LDL (Mục 1.2.3.b)
      - fg_bits  : số bit lưu mỗi hệ số f, g trong sk (6 bit / 5 bit)
      - FG_bits  : số bit lưu mỗi hệ số F trong sk (8 bit)
      - salt_len : độ dài salt r = 40 byte (r ∈ {0,1}^320)
    """
    Q = Q
    SALT_LEN = 40
    PARAMS: Dict[str, Dict] = {
        "falcon_512": {
            "n": 512,
            "logn": 9,
            "sig_byte_len": 666,
            "pk_byte_len": 897,
            "sk_byte_len": 1281,
            "sigma": 165.7366171829776,
            "sigmin": 1.2778336969128337,
            "beta2": 34034726,
            "fg_bits": 6,
            "FG_bits": 8,
        },
        "falcon_1024": {
            "n": 1024,
            "logn": 10,
            "sig_byte_len": 1280,
            "pk_byte_len": 1793,
            "sk_byte_len": 2305,
            "sigma": 168.38857144654395,
            "sigmin": 1.298280334344292,
            "beta2": 70265242,
            "fg_bits": 5,
            "FG_bits": 8,
        },
    }


# ==============================================================================
#   PHÉP BIẾN ĐỔI FOURIER NHANH TRÊN VÀNH R = Q[x]/(x^n + 1)   (Mục 1.2.2.b)
# ==============================================================================

class FFT:
    """FFT "kiểu Falcon" trên vành Q[x]/(x^n + 1), độ phức tạp O(n log n).

    [Đồ án - Mục 1.2.2.b] Đa thức được biểu diễn trong miền tần số bằng giá trị
    tại n nghiệm phức của x^n + 1. Cấu trúc đệ quy (cây FFT độ sâu log2 n):

        f(x) = f0(x²) + x·f1(x²)
        f(ζ)  = f0(ζ²) + ζ·f1(ζ²)
        f(−ζ) = f0(ζ²) − ζ·f1(ζ²)

    => mỗi nút của cây FFT rút gọn phép toán đa thức thành phép nhân/chia trên
    số phức. Nhờ đó nhân đa thức chỉ còn là nhân từng điểm (pointwise).

    Thứ tự nghiệm: roots(n) = [ζ0, −ζ0, ζ1, −ζ1, ...] với ζi² = roots(n/2)[i],
    roots(2) = [i, −i]. Thứ tự này khớp với split_fft / merge_fft bên dưới.
    """
    _roots_cache: Dict[int, List[complex]] = {}

    @classmethod
    def roots(cls, n: int) -> List[complex]:
        r = cls._roots_cache.get(n)
        if r is None:
            if n == 2:
                r = [1j, -1j]
            else:
                r = []
                for w in cls.roots(n // 2):
                    z = cmath.sqrt(w)      # ζ là căn bậc 2 của nghiệm bậc n/2
                    r.extend((z, -z))
            cls._roots_cache[n] = r
        return r

    # ---------- tách / gộp trong miền hệ số ----------
    @staticmethod
    def split(f: List) -> Tuple[List, List]:
        """f = f0(x²) + x·f1(x²): f0 = hệ số chẵn, f1 = hệ số lẻ."""
        return f[0::2], f[1::2]

    @staticmethod
    def merge(f0: List, f1: List) -> List:
        f = [0] * (2 * len(f0))
        f[0::2] = f0
        f[1::2] = f1
        return f

    # ---------- tách / gộp trong miền FFT ----------
    @classmethod
    def split_fft(cls, f_fft: List[complex]) -> Tuple[List[complex], List[complex]]:
        """f0(ζ²) = (f(ζ) + f(−ζ))/2 ;  f1(ζ²) = (f(ζ) − f(−ζ))/(2ζ)."""
        n = len(f_fft)
        w = cls.roots(n)
        f0 = [0j] * (n // 2)
        f1 = [0j] * (n // 2)
        for i in range(n // 2):
            a, b = f_fft[2 * i], f_fft[2 * i + 1]
            f0[i] = 0.5 * (a + b)
            f1[i] = 0.5 * (a - b) * w[2 * i].conjugate()   # 1/ζ = conj(ζ) vì |ζ| = 1
        return f0, f1

    @classmethod
    def merge_fft(cls, f0_fft: List[complex], f1_fft: List[complex]) -> List[complex]:
        """Phép "butterfly": f(±ζ) = f0(ζ²) ± ζ·f1(ζ²)."""
        n = 2 * len(f0_fft)
        w = cls.roots(n)
        f = [0j] * n
        for i in range(n // 2):
            t = w[2 * i] * f1_fft[i]
            f[2 * i] = f0_fft[i] + t
            f[2 * i + 1] = f0_fft[i] - t
        return f

    @classmethod
    def fft(cls, f: List) -> List[complex]:
        """Hệ số (thực) -> miền FFT (n giá trị phức)."""
        n = len(f)
        if n == 2:
            return [complex(f[0], f[1]), complex(f[0], -f[1])]
        f0, f1 = cls.split(f)
        return cls.merge_fft(cls.fft(f0), cls.fft(f1))

    @classmethod
    def ifft(cls, f_fft: List[complex]) -> List[float]:
        """Miền FFT -> hệ số thực (biến đổi ngược)."""
        n = len(f_fft)
        if n == 2:
            return [f_fft[0].real, f_fft[0].imag]
        f0_fft, f1_fft = cls.split_fft(f_fft)
        return cls.merge(cls.ifft(f0_fft), cls.ifft(f1_fft))

    # ---------- phép toán từng điểm trong miền FFT ----------
    @staticmethod
    def add_fft(a, b):
        return [x + y for x, y in zip(a, b)]

    @staticmethod
    def sub_fft(a, b):
        return [x - y for x, y in zip(a, b)]

    @staticmethod
    def mul_fft(a, b):
        return [x * y for x, y in zip(a, b)]

    @staticmethod
    def div_fft(a, b):
        return [x / y for x, y in zip(a, b)]

    @staticmethod
    def adj_fft(a):
        """Liên hợp Hermite f* (f*(x) = f(1/x)) <=> liên hợp phức từng điểm."""
        return [x.conjugate() for x in a]

    # ---------- phép toán đa thức thực qua FFT ----------
    @classmethod
    def mul(cls, a, b) -> List[float]:
        return cls.ifft(cls.mul_fft(cls.fft(a), cls.fft(b)))

    @classmethod
    def div(cls, a, b) -> List[float]:
        return cls.ifft(cls.div_fft(cls.fft(a), cls.fft(b)))

    @staticmethod
    def adj(a) -> List:
        """f*(x) = f0 − f_{n−1}·x − ... − f1·x^{n−1}."""
        return [a[0]] + [-x for x in a[:0:-1]]


# ==============================================================================
#   BIẾN ĐỔI SỐ HỌC (NTT) - NHÂN / CHIA ĐA THỨC TRONG Z_q[x]/(x^n + 1)
# ==============================================================================

class NTT:
    """Number Theoretic Transform modulo q = 12289 (chỉ dùng số nguyên).

    [Đồ án - Mục 1.2.1] Vì q ≡ 1 (mod 2n) nên x^n + 1 tách hoàn toàn trên Z_q:
    tồn tại ψ là căn nguyên thủy bậc 2n của đơn vị. Phép nhân "negacyclic"
    a·b mod (x^n + 1) được tính bằng:
        â_i = a_i·ψ^i  ->  NTT vòng (ω = ψ²)  ->  nhân từng điểm  ->  NTT ngược
        ->  nhân ψ^(−i)
    Dùng cho: tính khóa công khai h = g·f⁻¹ mod q (KeyGen) và s2·h (Verify),
    đúng yêu cầu "Verify chỉ dùng số nguyên mod q" (Mục 1.2.3.a).
    """
    _tables: Dict[int, Tuple] = {}

    @staticmethod
    def _primitive_root() -> int:
        # q − 1 = 2^12 · 3  -> g là phần tử sinh khi g^((q−1)/2) ≠ 1 và g^((q−1)/3) ≠ 1
        for g in range(2, Q):
            if pow(g, (Q - 1) // 2, Q) != 1 and pow(g, (Q - 1) // 3, Q) != 1:
                return g
        raise RuntimeError("Không tìm thấy phần tử sinh mod q")

    @classmethod
    def _get(cls, n: int):
        t = cls._tables.get(n)
        if t is None:
            g = cls._primitive_root()
            psi = pow(g, (Q - 1) // (2 * n), Q)          # căn bậc 2n của đơn vị
            psi_inv = pow(psi, Q - 2, Q)
            psi_pow = [pow(psi, i, Q) for i in range(n)]
            psi_inv_pow = [pow(psi_inv, i, Q) for i in range(n)]
            omega = psi * psi % Q                         # căn bậc n của đơn vị
            n_inv = pow(n, Q - 2, Q)
            bits = n.bit_length() - 1
            rev = [int(format(i, f"0{bits}b")[::-1], 2) for i in range(n)]
            t = (psi_pow, psi_inv_pow, omega, pow(omega, Q - 2, Q), n_inv, rev)
            cls._tables[n] = t
        return t

    @staticmethod
    def _cyclic(a: List[int], root: int, rev: List[int]) -> List[int]:
        """NTT vòng Cooley-Tukey lặp (radix-2)."""
        n = len(a)
        a = [a[r] for r in rev]
        length = 2
        while length <= n:
            half = length // 2
            w_len = pow(root, n // length, Q)
            ws = [1] * half
            for j in range(1, half):
                ws[j] = ws[j - 1] * w_len % Q
            for start in range(0, n, length):
                for j in range(half):
                    u = a[start + j]
                    v = a[start + j + half] * ws[j] % Q
                    a[start + j] = (u + v) % Q
                    a[start + j + half] = (u - v) % Q
            length <<= 1
        return a

    @classmethod
    def ntt(cls, a: List[int]) -> List[int]:
        psi_pow, _, omega, _, _, rev = cls._get(len(a))
        return cls._cyclic([(x * p) % Q for x, p in zip(a, psi_pow)], omega, rev)

    @classmethod
    def intt(cls, a_hat: List[int]) -> List[int]:
        _, psi_inv_pow, _, omega_inv, n_inv, rev = cls._get(len(a_hat))
        a = cls._cyclic(a_hat, omega_inv, rev)
        return [(x * n_inv % Q) * p % Q for x, p in zip(a, psi_inv_pow)]

    @classmethod
    def mul_zq(cls, a: List[int], b: List[int]) -> List[int]:
        return cls.intt([(x * y) % Q for x, y in zip(cls.ntt(a), cls.ntt(b))])

    @classmethod
    def div_zq(cls, a: List[int], b: List[int]) -> List[int]:
        """a / b mod (q, x^n + 1). Báo lỗi nếu b không khả nghịch."""
        b_hat = cls.ntt(b)
        if any(x == 0 for x in b_hat):
            raise ZeroDivisionError("Đa thức không khả nghịch modulo q")
        a_hat = cls.ntt(a)
        return cls.intt([(x * pow(y, Q - 2, Q)) % Q for x, y in zip(a_hat, b_hat)])

    @staticmethod
    def is_invertible(f: List[int]) -> bool:
        return all(x != 0 for x in NTT.ntt([c % Q for c in f]))


# ==============================================================================
#   LẤY MẪU GAUSSIAN RỜI RẠC 1 CHIỀU - SamplerZ   (Mục 1.2.2.b, 1.2.3.b)
# ==============================================================================

class SamplerZ:
    """Lấy mẫu z ~ D_{Z, σ', μ} (Gaussian rời rạc tâm μ, độ lệch σ').

    [Đồ án - Mục 1.2.2.b] Tại mỗi lá của cây FFT/LDL, ffSampling "lấy mẫu
    Gaussian 1 chiều trên các số thực". Cài đặt theo thuật toán SamplerZ:
      1) BaseSampler: lấy z0 từ nửa Gaussian D_{Z+, σmax} bằng bảng RCDT
         (Reverse Cumulative Distribution Table) 72 bit, σmax = 1.8205.
      2) z = b + (2b − 1)·z0 với bit ngẫu nhiên b (đối xứng hóa).
      3) Chấp nhận z với xác suất  (σmin/σ')·exp(−(z−r)²/(2σ'²) + z0²/(2σmax²))
         bằng BerExp (lấy mẫu Bernoulli với xấp xỉ đa thức của exp).
    Hệ số σmin/σ' (ccs) đảm bảo xác suất chấp nhận không phụ thuộc σ' ->
    chống rò rỉ kênh thời gian (Mục 1.2.3.b).
    """
    SIGMA_MAX = 1.8205
    INV_2SIGMA2 = 1.0 / (2.0 * SIGMA_MAX ** 2)
    RCDT_PREC = 72
    LN2 = 0.69314718056
    ILN2 = 1.44269504089
    # Bảng RCDT: RCDT[i] = 2^72 · P(z0 > i)
    RCDT = [
        3024686241123004913666, 1564742784480091954050, 636254429462080897535,
        199560484645026482916, 47667343854657281903, 8595902006365044063,
        1163297957344668388, 117656387352093658, 8867391802663976,
        496969357462633, 20680885154299, 638331848991,
        14602316184, 247426747, 3104126,
        28824, 198, 1,
    ]
    # Hệ số đa thức xấp xỉ exp(−x) (≈ 2^63 / k!), tính theo sơ đồ Horner
    C = [
        0x00000004741183A3, 0x00000036548CFC06, 0x0000024FDCBF140A,
        0x0000171D939DE045, 0x0000D00CF58F6F84, 0x000680681CF796E3,
        0x002D82D8305B0FEA, 0x011111110E066FD0, 0x0555555555070F00,
        0x155555555581FF00, 0x400000000002B400, 0x7FFFFFFFFFFF4800,
        0x8000000000000000,
    ]

    def __init__(self):
        self._buf = b""
        self._pos = 0

    def random_bytes(self, k: int) -> bytes:
        """CSPRNG (secrets) có bộ đệm để giảm số lần gọi hệ điều hành."""
        if self._pos + k > len(self._buf):
            self._buf = secrets.token_bytes(max(4096, k))
            self._pos = 0
        out = self._buf[self._pos:self._pos + k]
        self._pos += k
        return out

    def base_sampler(self) -> int:
        u = int.from_bytes(self.random_bytes(self.RCDT_PREC >> 3), "little")
        return sum(1 for e in self.RCDT if u < e)

    @classmethod
    def approx_exp(cls, x: float, ccs: float) -> int:
        """Trả về ≈ 2^64 · ccs · exp(−x) (số nguyên 64 bit), với 0 ≤ x < ln 2."""
        y = cls.C[0]
        z = int(x * (1 << 63))
        for c in cls.C[1:]:
            y = c - ((z * y) >> 63)
        z = int(ccs * (1 << 63)) << 1
        return (z * y) >> 63

    def ber_exp(self, x: float, ccs: float) -> bool:
        """Trả về True với xác suất ≈ ccs · exp(−x)."""
        s = int(x * self.ILN2)            # x = s·ln2 + r
        r = x - s * self.LN2
        s = min(s, 63)
        z = (self.approx_exp(r, ccs) - 1) >> s
        w = 0
        for i in range(56, -8, -8):       # so sánh từng byte với số ngẫu nhiên
            p = self.random_bytes(1)[0]
            w = p - ((z >> i) & 0xFF)
            if w:
                break
        return w < 0

    def sample(self, mu: float, sigma: float, sigmin: float) -> int:
        s = math.floor(mu)
        r = mu - s
        dss = 1.0 / (2.0 * sigma * sigma)
        ccs = sigmin / sigma
        while True:
            z0 = self.base_sampler()
            b = self.random_bytes(1)[0] & 1
            z = b + (2 * b - 1) * z0
            x = ((z - r) ** 2) * dss - (z0 ** 2) * self.INV_2SIGMA2
            if self.ber_exp(x, ccs):
                return z + s


# ==============================================================================
#   SINH KHÓA NTRU: NTRUGen + NTRUSolve   (Mục 1.2.1, 1.2.4.a, 2.2.1.a)
# ==============================================================================

class NTRUEngine:
    """Sinh (f, g, F, G) thỏa phương trình NTRU  f·G − g·F = q  mod (x^n + 1).

    [Đồ án - Mục 2.2.1.a]
      1) Lấy mẫu f, g hệ số nhỏ theo Gaussian rời rạc σ_{f,g} ≈ 1.17·√(q/2n)
      2) Giải NTRUSolve tìm F, G hệ số nhỏ
      3) Kiểm tra f khả nghịch mod q và chuẩn Gram-Schmidt ≤ 1.17·√q
    NTRUSolve là thuật toán đệ quy (Pornin-Prest):
      - Hạ bậc bằng chuẩn trường (field norm) N(f)(x²) = f(x)·f(−x)
        cho tới n = 1, khi đó giải f·G − g·F = q trên Z bằng Euclid mở rộng.
      - Nâng nghiệm lên: F = F'(x²)·g(−x), G = G'(x²)·f(−x).
      - Rút gọn Babai: (F, G) ← (F, G) − k·(f, g), k = ⌊(F f* + G g*)/(f f* + g g*)⌉,
        k được tính xấp xỉ bằng FFT số phức (Mục 2.2.1.a: "kết hợp FFT").
    Phép nhân số nguyên lớn dùng kỹ thuật Kronecker (đóng gói đa thức thành một
    số nguyên lớn) - chính xác tuyệt đối, nhanh hơn nhân trực tiếp O(n²).
    """
    SIGMA_FG_4096 = 1.43300980528773   # = 1.17·√(q/8192); cộng 4096/n mẫu -> σ_{f,g}

    def __init__(self, n: int, sampler: Optional[SamplerZ] = None):
        self.n = n
        self.sampler = sampler or SamplerZ()

    # ---------- số học đa thức nguyên chính xác ----------
    @staticmethod
    def poly_mul_int(a: List[int], b: List[int]) -> List[int]:
        """a·b mod (x^n + 1) với hệ số nguyên tùy ý (Kronecker substitution)."""
        n = len(a)
        ma = max(abs(x) for x in a)
        mb = max(abs(x) for x in b)
        if ma == 0 or mb == 0:
            return [0] * n
        # Mỗi hệ số tích |c_i| ≤ n·max|a|·max|b| < 2^(B−1)
        B = ma.bit_length() + mb.bit_length() + n.bit_length() + 2
        B = (B + 7) // 8 * 8
        nb = B // 8
        half = 1 << (B - 1)

        def pack(p):
            # Mã hóa từng hệ số có dấu thành chữ số không âm (+2^(B−1))
            data = b"".join((x + half).to_bytes(nb, "little") for x in p)
            offset = int.from_bytes(half.to_bytes(nb, "little") * len(p), "little")
            return int.from_bytes(data, "little") - offset

        prod = pack(a) * pack(b)
        m = 2 * n - 1
        offset = int.from_bytes(half.to_bytes(nb, "little") * m, "little")
        raw = (prod + offset).to_bytes(nb * m, "little")
        c = [int.from_bytes(raw[i * nb:(i + 1) * nb], "little") - half for i in range(m)]
        # Rút gọn x^n ≡ −1
        res = c[:n]
        for i in range(n, m):
            res[i - n] -= c[i]
        return res

    @staticmethod
    def galois_conjugate(a: List[int]) -> List[int]:
        """a(x) -> a(−x)."""
        return [x if i % 2 == 0 else -x for i, x in enumerate(a)]

    @classmethod
    def field_norm(cls, a: List[int]) -> List[int]:
        """N(a)(x²) = a(x)·a(−x) = a_e(x²)² − x²·a_o(x²)², trả về đa thức bậc n/2."""
        ae, ao = a[0::2], a[1::2]
        ae2 = cls.poly_mul_int(ae, ae)
        ao2 = cls.poly_mul_int(ao, ao)
        res = ae2[:]
        m = len(ae)
        for i in range(m - 1):
            res[i + 1] -= ao2[i]
        res[0] += ao2[m - 1]          # x·x^(m−1) = x^m ≡ −1
        return res

    @staticmethod
    def lift(a: List[int]) -> List[int]:
        """a(x) -> a(x²)."""
        res = [0] * (2 * len(a))
        res[0::2] = a
        return res

    @staticmethod
    def _bitsize(a: int) -> int:
        val, res = abs(a), 0
        while val:
            res += 8
            val >>= 8
        return res

    @classmethod
    def reduce(cls, f, g, F, G):
        """Rút gọn Babai (F, G) theo (f, g) - dùng FFT trên 53 bit cao nhất."""
        size = max(53, *(cls._bitsize(x) for x in (min(f), max(f), min(g), max(g))))
        fa = FFT.fft([x >> (size - 53) for x in f])
        ga = FFT.fft([x >> (size - 53) for x in g])
        den = FFT.add_fft(FFT.mul_fft(fa, FFT.adj_fft(fa)), FFT.mul_fft(ga, FFT.adj_fft(ga)))
        while True:
            Size = max(53, *(cls._bitsize(x) for x in (min(F), max(F), min(G), max(G))))
            if Size < size:
                break
            Fa = FFT.fft([x >> (Size - 53) for x in F])
            Ga = FFT.fft([x >> (Size - 53) for x in G])
            num = FFT.add_fft(FFT.mul_fft(Fa, FFT.adj_fft(fa)), FFT.mul_fft(Ga, FFT.adj_fft(ga)))
            k = [int(round(x)) for x in FFT.ifft(FFT.div_fft(num, den))]
            if not any(k):
                break
            fk = cls.poly_mul_int(f, k)
            gk = cls.poly_mul_int(g, k)
            shift = Size - size
            F = [x - (y << shift) for x, y in zip(F, fk)]
            G = [x - (y << shift) for x, y in zip(G, gk)]
        return F, G

    @staticmethod
    def xgcd(a: int, b: int) -> Tuple[int, int, int]:
        """Euclid mở rộng: trả về (d, u, v) với a·u + b·v = d = gcd(a, b)."""
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b:
            qt, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - qt * x1
            y0, y1 = y1, y0 - qt * y1
        return a, x0, y0

    @classmethod
    def ntru_solve(cls, f: List[int], g: List[int]) -> Tuple[List[int], List[int]]:
        """NTRUSolve đệ quy: tìm (F, G) với f·G − g·F = q."""
        if len(f) == 1:
            d, u, v = cls.xgcd(f[0], g[0])
            if d != 1:
                raise ValueError("gcd(N(f), N(g)) ≠ 1")
            # f·u + g·v = 1  =>  f·(q·u) − g·(−q·v) = q
            return [-Q * v], [Q * u]
        Fp, Gp = cls.ntru_solve(cls.field_norm(f), cls.field_norm(g))
        F = cls.poly_mul_int(cls.lift(Fp), cls.galois_conjugate(g))
        G = cls.poly_mul_int(cls.lift(Gp), cls.galois_conjugate(f))
        return cls.reduce(f, g, F, G)

    @staticmethod
    def gs_norm(f: List[int], g: List[int]) -> float:
        """Bình phương chuẩn Gram-Schmidt lớn nhất của cơ sở B = [[g, −f], [G, −F]]."""
        sq_fg = sum(x * x for x in f) + sum(x * x for x in g)
        ffgg = FFT.add_fft(FFT.mul_fft(FFT.fft(f), FFT.adj_fft(FFT.fft(f))),
                           FFT.mul_fft(FFT.fft(g), FFT.adj_fft(FFT.fft(g))))
        Ft = FFT.ifft(FFT.div_fft(FFT.adj_fft(FFT.fft(g)), ffgg))
        Gt = FFT.ifft(FFT.div_fft(FFT.adj_fft(FFT.fft(f)), ffgg))
        sq_FG = (Q ** 2) * (sum(x * x for x in Ft) + sum(x * x for x in Gt))
        return max(sq_fg, sq_FG)

    def gen_poly(self) -> List[int]:
        """Đa thức hệ số ~ D_{Z, σ_{f,g}}: tổng 4096/n mẫu Gaussian σ = 1.433."""
        n = self.n
        k = 4096 // n
        sig = self.SIGMA_FG_4096
        samples = [self.sampler.sample(0.0, sig, sig - 0.001) for _ in range(4096)]
        return [sum(samples[i * k:(i + 1) * k]) for i in range(n)]

    def ntru_gen(self, fg_limit: int, FG_limit: int) -> Tuple[List[int], List[int], List[int], List[int], int]:
        """NTRUGen: lặp đến khi được (f, g, F, G) hợp lệ. Trả thêm số lần thử."""
        attempts = 0
        while True:
            attempts += 1
            f = self.gen_poly()
            g = self.gen_poly()
            # Hệ số phải vừa định dạng lưu trữ sk (Mục 2.2.1.b)
            if max(abs(x) for x in f + g) >= fg_limit:
                continue
            # Chuẩn Gram-Schmidt ≤ (1.17)²·q  (Mục 1.2.3.b)
            if self.gs_norm(f, g) > (1.17 ** 2) * Q:
                continue
            # f phải khả nghịch mod q để tính h = g·f⁻¹
            if not NTT.is_invertible(f):
                continue
            try:
                F, G = self.ntru_solve(f, g)
            except ValueError:
                continue
            if max(abs(x) for x in F + G) >= FG_limit:
                continue
            # Kiểm tra lại phương trình NTRU: f·G − g·F = q
            fG = self.poly_mul_int(f, G)
            gF = self.poly_mul_int(g, F)
            if fG[0] - gF[0] != Q or any(a - b for a, b in zip(fG[1:], gF[1:])):
                continue
            return f, g, F, G, attempts


# ==============================================================================
#   CÂY LDL (FALCON TREE) VÀ ffSampling   (Mục 1.2.2.b, 3.2.1)
# ==============================================================================

class FalconSampler:
    """Fast Fourier Sampling trên cây phân tách LDL.

    [Đồ án - Mục 1.2.2.b]
      - Ma trận Gram G = B·B* của cơ sở bí mật B = [[g, −f], [G, −F]] được tính
        trong miền FFT, rồi phân tích LDL*: G = L·D·L*.
      - ffLDL đệ quy tạo "cây LDL" độ sâu log2 n: mỗi nút lưu L10, hai nhánh con
        là cây của D00 và D11 sau khi tách (split_fft) xuống vành bậc n/2.
      - Lá của cây được chuẩn hóa thành σ' = σ / √(D_ii)  (∈ [σmin, σmax]).
      - ffSampling duyệt cây từ gốc đến lá; tại lá gọi SamplerZ (Gaussian 1 chiều),
        rồi gộp (merge_fft) các mẫu ngược lên để được z = (z0, z1).
    Nhờ đó điểm lưới v = z·B có phân phối Gaussian độc lập với B -> chữ ký
    không làm lộ khóa bí mật (chống tấn công học lưới LLA).
    """

    def __init__(self, n: int, sigma: float, sigmin: float):
        self.n = n
        self.sigma = sigma
        self.sigmin = sigmin

    @staticmethod
    def gram_fft(B_fft):
        """G = B·B*  (ma trận 2×2 các đa thức, trong miền FFT)."""
        [[a, b], [c, d]] = B_fft
        adj = FFT.adj_fft
        g00 = FFT.add_fft(FFT.mul_fft(a, adj(a)), FFT.mul_fft(b, adj(b)))
        g01 = FFT.add_fft(FFT.mul_fft(a, adj(c)), FFT.mul_fft(b, adj(d)))
        g10 = adj(g01)
        g11 = FFT.add_fft(FFT.mul_fft(c, adj(c)), FFT.mul_fft(d, adj(d)))
        return [[g00, g01], [g10, g11]]

    @classmethod
    def ffldl(cls, G):
        """ffLDL*: trả về cây (L10, cây_trái, cây_phải); lá là số thực D_ii."""
        [[g00, _], [g10, g11]] = G
        # Phân tích LDL* 2×2:  L10 = G10/G00,  D00 = G00,  D11 = G11 − |L10|²·G00
        L10 = FFT.div_fft(g10, g00)
        D00 = g00
        D11 = FFT.sub_fft(g11, FFT.mul_fft(FFT.mul_fft(L10, FFT.adj_fft(L10)), g00))
        if len(g00) == 2:
            # Tại n = 2: D00, D11 là hằng số thực -> lá của cây
            return (L10, D00[0].real, D11[0].real)
        d00, d01 = FFT.split_fft(D00)
        d10, d11 = FFT.split_fft(D11)
        G0 = [[d00, d01], [FFT.adj_fft(d01), d00]]
        G1 = [[d10, d11], [FFT.adj_fft(d11), d10]]
        return (L10, cls.ffldl(G0), cls.ffldl(G1))

    def normalize_tree(self, tree):
        """Lá: D_ii -> σ' = σ / √D_ii."""
        L10, left, right = tree
        left = self.sigma / math.sqrt(left) if isinstance(left, float) else self.normalize_tree(left)
        right = self.sigma / math.sqrt(right) if isinstance(right, float) else self.normalize_tree(right)
        return (L10, left, right)

    def build_tree(self, B_fft):
        return self.normalize_tree(self.ffldl(self.gram_fft(B_fft)))

    def ff_sampling(self, t, tree, rng: SamplerZ):
        """ffSampling(t, T): trả về z = (z0, z1) trong miền FFT, z ≈ t."""
        t0, t1 = t
        if isinstance(tree, float):
            # Lá (n = 1): lấy mẫu Gaussian 1 chiều tâm t, độ lệch σ'
            return ([complex(rng.sample(t0[0].real, tree, self.sigmin))],
                    [complex(rng.sample(t1[0].real, tree, self.sigmin))])
        L10, T0, T1 = tree
        # Nhánh phải trước: z1 ← ffSampling(t1, T1)
        z1 = FFT.merge_fft(*self.ff_sampling(FFT.split_fft(t1), T1, rng))
        # Cập nhật tâm: t0' = t0 + (t1 − z1)·L10
        t0b = FFT.add_fft(t0, FFT.mul_fft(FFT.sub_fft(t1, z1), L10))
        # Nhánh trái: z0 ← ffSampling(t0', T0)
        z0 = FFT.merge_fft(*self.ff_sampling(FFT.split_fft(t0b), T0, rng))
        return z0, z1


# ==============================================================================
#   MÃ HÓA KHÓA VÀ CHỮ KÝ   (Mục 2.2.1.b, 1.2.4.b "Compress")
# ==============================================================================

class FalconEncoding:
    """Định dạng nhị phân theo đặc tả Falcon.

    [Đồ án - Mục 2.2.1.b]
      - pk  = header(0x00 + logn) || h, mỗi hệ số 14 bit  -> 1 + 14n/8 byte (897 / 1793)
      - sk  = header(0x50 + logn) || f || g || F; f, g dùng 6 bit (n=512) hoặc
              5 bit (n=1024), F dùng 8 bit; G KHÔNG lưu vì tính lại được từ
              f·G − g·F = q  -> 1281 / 2305 byte.
    [Đồ án - Mục 1.2.4.b] Compress(s2): mỗi hệ số = 1 bit dấu || 7 bit thấp ||
      phần cao mã hóa unary (k số 0 rồi số 1). Chữ ký cố định độ dài:
      sig = header(0x30 + logn) || salt(40) || Compress(s2) đệm 0  -> 666 / 1280 byte.
    """

    @staticmethod
    def _pack(values: List[int], bits: int) -> bytes:
        acc = 0
        for v in values:
            acc = (acc << bits) | v
        total = bits * len(values)
        pad = (-total) % 8
        return (acc << pad).to_bytes((total + pad) // 8, "big")

    @staticmethod
    def _unpack(data: bytes, bits: int, count: int) -> List[int]:
        total = bits * count
        acc = int.from_bytes(data, "big") >> (len(data) * 8 - total)
        mask = (1 << bits) - 1
        return [(acc >> (bits * (count - 1 - i))) & mask for i in range(count)]

    # ---------- khóa công khai ----------
    @classmethod
    def encode_pk(cls, h: List[int], logn: int) -> bytes:
        return bytes([0x00 + logn]) + cls._pack(h, 14)

    @classmethod
    def decode_pk(cls, pk: bytes, n: int, logn: int) -> List[int]:
        if len(pk) != 1 + 14 * n // 8 or pk[0] != logn:
            raise ValueError("Khóa công khai sai định dạng")
        h = cls._unpack(pk[1:], 14, n)
        if any(x >= Q for x in h):
            raise ValueError("Hệ số khóa công khai ≥ q")
        return h

    # ---------- khóa bí mật ----------
    @classmethod
    def _pack_signed(cls, values: List[int], bits: int) -> bytes:
        lim = 1 << (bits - 1)
        if any(not (-lim < v < lim) for v in values):
            raise ValueError("Hệ số vượt quá số bit lưu trữ")
        return cls._pack([v & ((1 << bits) - 1) for v in values], bits)

    @classmethod
    def _unpack_signed(cls, data: bytes, bits: int, count: int) -> List[int]:
        lim = 1 << (bits - 1)
        out = []
        for v in cls._unpack(data, bits, count):
            if v == lim:                       # giá trị −2^(bits−1) bị cấm
                raise ValueError("Khóa bí mật sai định dạng")
            out.append(v - (1 << bits) if v > lim else v)
        return out

    @classmethod
    def encode_sk(cls, f, g, F, logn: int, fg_bits: int, FG_bits: int) -> bytes:
        return (bytes([0x50 + logn]) + cls._pack_signed(f, fg_bits)
                + cls._pack_signed(g, fg_bits) + cls._pack_signed(F, FG_bits))

    @classmethod
    def decode_sk(cls, sk: bytes, n: int, logn: int, fg_bits: int, FG_bits: int):
        lf = fg_bits * n // 8
        lF = FG_bits * n // 8
        if len(sk) != 1 + 2 * lf + lF or sk[0] != 0x50 + logn:
            raise ValueError("Khóa bí mật sai định dạng")
        f = cls._unpack_signed(sk[1:1 + lf], fg_bits, n)
        g = cls._unpack_signed(sk[1 + lf:1 + 2 * lf], fg_bits, n)
        F = cls._unpack_signed(sk[1 + 2 * lf:], FG_bits, n)
        return f, g, F

    # ---------- nén chữ ký ----------
    @staticmethod
    def compress(v: List[int], slen: int) -> Optional[bytes]:
        bits = []
        for c in v:
            a = abs(c)
            if a > 2047:
                return None
            bits.append(("1" if c < 0 else "0") + format(a & 0x7F, "07b") + "0" * (a >> 7) + "1")
        s = "".join(bits)
        if len(s) > 8 * slen:
            return None                        # chữ ký quá dài -> ký lại
        s += "0" * (8 * slen - len(s))
        return int(s, 2).to_bytes(slen, "big")

    @staticmethod
    def decompress(data: bytes, n: int) -> Optional[List[int]]:
        s = format(int.from_bytes(data, "big"), f"0{8 * len(data)}b")
        v, i, L = [], 0, len(s)
        try:
            for _ in range(n):
                sign = s[i]
                low = int(s[i + 1:i + 8], 2)
                i += 8
                high = 0
                while s[i] == "0":
                    high += 1
                    i += 1
                    if high > 15:
                        return None
                i += 1
                val = (high << 7) | low
                if sign == "1":
                    if val == 0:
                        return None            # "−0" không hợp lệ
                    val = -val
                if abs(val) > 2047:
                    return None
                v.append(val)
        except IndexError:
            return None
        if "1" in s[i:L]:
            return None                        # phần đệm phải toàn bit 0
        return v


# ==============================================================================
#   KHỐI KÝ SỐ FALCON: HashToPoint, KeyGen, Sign, Verify   (Mục 1.2.4, 2.2)
# ==============================================================================

class _ExpandedKey:
    """Khóa bí mật đã "mở rộng": cơ sở B ở miền FFT + cây LDL đã chuẩn hóa."""
    __slots__ = ("B_fft", "tree", "h")

    def __init__(self, B_fft, tree, h):
        self.B_fft = B_fft
        self.tree = tree
        self.h = h


class FalconEngine:
    """Khối Ký số Falcon (Tầng 3 - Mục 2.3.1, 3.2.1)."""
    _cache: Dict[Tuple[str, bytes], _ExpandedKey] = {}
    _cache_lock = threading.Lock()

    def __init__(self, algorithm: str = "falcon_512"):
        if algorithm not in FalconNISTParams.PARAMS:
            algorithm = "falcon_512"
        self.algorithm = algorithm
        self.params = FalconNISTParams.PARAMS[algorithm]
        self.n = self.params["n"]
        self.logn = self.params["logn"]
        self.q = Q
        self.sampler = FalconSampler(self.n, self.params["sigma"], self.params["sigmin"])
        self.last_sign_info: Dict[str, int] = {}
        self.last_keygen_info: Dict[str, int] = {}

    # ------------------------------------------------------------------
    def hash_to_point(self, message: bytes, salt: bytes) -> List[int]:
        """HashToPoint: (r, m) -> c ∈ Z_q[x]/(x^n + 1).

        [Đồ án - Mục 1.2.2.a] c = HashToPoint(r || m).
        Theo đặc tả Falcon / FIPS 206: dùng hàm XOF SHAKE-256(r || m), đọc
        từng cặp 2 byte thành số 16 bit t; chỉ nhận t < 5q = 61445 (Rejection
        Sampling, để c_i = t mod q phân phối đều) cho đến khi đủ n hệ số.
        Lưu ý: Mục 2.2.2.a và 3.2.1 của báo cáo đang ghi "SHA-512"; chuẩn Falcon
        dùng SHAKE-256 (đã kiểm chứng với vector KAT của NIST).
        """
        n = self.n
        k5q = (1 << 16) // Q * Q              # 61445
        out_len = 4 * n
        while True:
            stream = hashlib.shake_256(salt + message).digest(out_len)
            c = []
            for i in range(0, out_len, 2):
                t = (stream[i] << 8) | stream[i + 1]
                if t < k5q:
                    c.append(t % Q)
                    if len(c) == n:
                        return c
            out_len *= 2                      # hiếm khi xảy ra: đọc thêm luồng XOF

    # ------------------------------------------------------------------
    def keygen(self) -> Tuple[bytes, bytes]:
        """KeyGen (Mục 1.2.4.a, 2.2.1.a).

          1) NTRUGen: f, g ~ Gaussian rời rạc; NTRUSolve -> F, G (f·G − g·F = q)
          2) h = g · f⁻¹ mod q   (tính bằng NTT)
          3) sk = (f, g, F) mã hóa chuẩn; cây LDL được dựng lại khi ký
          4) pk = mã hóa 14 bit của h
        Trả về (sk_bytes, pk_bytes) đúng 1281/897 hoặc 2305/1793 byte.
        """
        p = self.params
        ntru = NTRUEngine(self.n)
        f, g, F, G, attempts = ntru.ntru_gen(1 << (p["fg_bits"] - 1), 1 << (p["FG_bits"] - 1))
        h = NTT.div_zq([x % Q for x in g], [x % Q for x in f])
        sk = FalconEncoding.encode_sk(f, g, F, self.logn, p["fg_bits"], p["FG_bits"])
        pk = FalconEncoding.encode_pk(h, self.logn)
        assert len(sk) == p["sk_byte_len"] and len(pk) == p["pk_byte_len"]
        self.last_keygen_info = {"attempts": attempts}
        return sk, pk

    # ------------------------------------------------------------------
    def decode_secret_key(self, sk: bytes):
        """Giải mã sk -> (f, g, F, G); G được tính lại từ phương trình NTRU."""
        p = self.params
        f, g, F = FalconEncoding.decode_sk(sk, self.n, self.logn, p["fg_bits"], p["FG_bits"])
        # G = g·F / f  mod q  (vì f·G − g·F = q ≡ 0 mod q), đưa về khoảng (−q/2, q/2]
        G = NTT.div_zq([x % Q for x in NTRUEngine.poly_mul_int(g, F)], [x % Q for x in f])
        G = [x - Q if x > Q // 2 else x for x in G]
        if max(abs(x) for x in G) >= (1 << (p["FG_bits"] - 1)):
            raise ValueError("Khóa bí mật không hợp lệ (G vượt giới hạn)")
        return f, g, F, G

    def expand_secret_key(self, sk: bytes) -> _ExpandedKey:
        """Giải mã sk, tính lại G, dựng cơ sở B (FFT) và cây LDL (có bộ nhớ đệm)."""
        key = (self.algorithm, hashlib.sha256(sk).digest())
        with self._cache_lock:
            ek = self._cache.get(key)
        if ek is not None:
            return ek
        f, g, F, G = self.decode_secret_key(sk)
        # Cơ sở bí mật B = [[g, −f], [G, −F]]  (Mục 1.2.1)
        B = [[g, [-x for x in f]], [G, [-x for x in F]]]
        B_fft = [[FFT.fft(e) for e in row] for row in B]
        tree = self.sampler.build_tree(B_fft)
        h = NTT.div_zq([x % Q for x in g], [x % Q for x in f])
        ek = _ExpandedKey(B_fft, tree, h)
        with self._cache_lock:
            if len(self._cache) > 16:
                self._cache.clear()
            self._cache[key] = ek
        return ek

    def public_key_from_secret(self, sk: bytes) -> bytes:
        return FalconEncoding.encode_pk(self.expand_secret_key(sk).h, self.logn)

    # ------------------------------------------------------------------
    def _sample_preimage(self, c: List[int], ek: _ExpandedKey, rng: SamplerZ) -> Tuple[List[int], List[int]]:
        """Tìm (s1, s2) ngắn với s1 + s2·h = c (mod q) bằng ffSampling."""
        [[a, b], [cc, d]] = ek.B_fft
        c_fft = FFT.fft(c)
        # Tọa độ của điểm đích (c, 0) trong cơ sở B: t = (c, 0)·B⁻¹,
        # B⁻¹ = (1/q)·[[−F, f], [−G, g]]  =>  t0 = c·(−F)/q,  t1 = c·f/q
        t0 = [x * y / Q for x, y in zip(c_fft, d)]
        t1 = [-x * y / Q for x, y in zip(c_fft, b)]
        z0, z1 = self.sampler.ff_sampling((t0, t1), ek.tree, rng)
        # Điểm lưới v = z·B gần (c, 0)
        v0 = FFT.add_fft(FFT.mul_fft(z0, a), FFT.mul_fft(z1, cc))
        v1 = FFT.add_fft(FFT.mul_fft(z0, b), FFT.mul_fft(z1, d))
        v0 = [int(round(x)) for x in FFT.ifft(v0)]
        v1 = [int(round(x)) for x in FFT.ifft(v1)]
        # s = (c, 0) − v  =>  s1 = c − v0,  s2 = −v1
        return [x - y for x, y in zip(c, v0)], [-x for x in v1]

    def sign(self, sk: bytes, message: bytes) -> bytes:
        """Sign (Mục 1.2.4.b, 2.2.2.a Bước 5).

          + Sinh salt r ∈ {0,1}^320 (40 byte) bằng CSPRNG (ký ngẫu nhiên - Mục 1.2.3.d)
          + c = HashToPoint(r || m)
          + ffSampling với cây LDL của sk -> (s1, s2) thỏa s1 + s2·h = c (mod q)
          + Kiểm tra ‖(s1, s2)‖² ≤ β²; nếu vượt -> lấy mẫu lại
          + σ = header || r || Compress(s2)   (độ dài cố định 666 / 1280 byte)
        Lưu ý: cấu trúc "salt + s2 (int16_le) + tag SHA-256" ở Mục 3.2.1 của báo
        cáo thuộc bản mô phỏng cũ; bản cài đặt này dùng đúng định dạng chuẩn ở trên.
        """
        p = self.params
        ek = self.expand_secret_key(sk)
        rng = SamplerZ()
        slen = p["sig_byte_len"] - 1 - FalconNISTParams.SALT_LEN
        attempts = 0
        while True:
            attempts += 1
            salt = secrets.token_bytes(FalconNISTParams.SALT_LEN)
            c = self.hash_to_point(message, salt)
            s1, s2 = self._sample_preimage(c, ek, rng)
            norm2 = sum(x * x for x in s1) + sum(x * x for x in s2)
            if norm2 > p["beta2"]:
                continue
            enc = FalconEncoding.compress(s2, slen)
            if enc is None:
                continue
            self.last_sign_info = {"attempts": attempts, "norm2": norm2}
            return bytes([0x30 + self.logn]) + salt + enc

    # ------------------------------------------------------------------
    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        """Verify (Mục 1.2.4.c, 2.2.2.b Bước 5-6) - chỉ dùng số nguyên mod q.

          1) Giải mã pk -> h ; tách σ -> (r, Compress(s2)) và giải nén s2
          2) c' = HashToPoint(r || m)
          3) s1 = c' − s2·h mod q, đưa về khoảng (−q/2, q/2]
          4) Chấp nhận khi ‖(s1, s2)‖² ≤ β²
        """
        p = self.params
        try:
            if len(signature) != p["sig_byte_len"] or signature[0] != 0x30 + self.logn:
                return False
            h = FalconEncoding.decode_pk(pk, self.n, self.logn)
            salt = signature[1:1 + FalconNISTParams.SALT_LEN]
            s2 = FalconEncoding.decompress(signature[1 + FalconNISTParams.SALT_LEN:], self.n)
            if s2 is None:
                return False
            c = self.hash_to_point(message, salt)
            s2h = NTT.mul_zq([x % Q for x in s2], h)
            s1 = [(ci - x) % Q for ci, x in zip(c, s2h)]
            s1 = [x - Q if x > Q // 2 else x for x in s1]
            norm2 = sum(x * x for x in s1) + sum(x * x for x in s2)
            return norm2 <= p["beta2"]
        except (ValueError, IndexError):
            return False
