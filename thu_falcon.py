from falcon_core import FalconEngine
e = FalconEngine("falcon_512")
sk, pk = e.keygen()
sig = e.sign(sk, b"Xin chao")
print(len(sk), len(pk), len(sig), e.verify(pk, b"Xin chao", sig))