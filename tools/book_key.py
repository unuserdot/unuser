"""Recomputes the book key: an x25519 public key with no known private key.
sha256("UNUSER book key v1 #i") with the top bit cleared, for the first i that is a point on Curve25519,
then multiplied by 8 (cofactor) so it lies in the prime-order group. Prints the 32 bytes as in BOOK_KEY."""
import hashlib
p = 2**255 - 19; L = 2**252 + 27742317777372353535851937790883648493

def ladder(k, u):  # x-only Montgomery ladder without clamping; returns (X, Z) of k*P
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(k.bit_length())):
        b = (k >> t) & 1; swap ^= b
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        swap = b
        a, bb = (x2 + z2) % p, (x2 - z2) % p
        aa, b2 = a * a % p, bb * bb % p; e = (aa - b2) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * bb % p
        x3, z3 = (da + cb) ** 2 % p, x1 * (da - cb) ** 2 % p
        x2, z2 = aa * b2 % p, e * (aa + 121665 * e) % p
    if swap: x2, z2 = x3, z3
    return x2, z2

for i in range(1000):
    k = bytearray(hashlib.sha256(b"UNUSER book key v1 #%d" % i).digest()); k[31] &= 0x7F
    u = int.from_bytes(k, "little")
    if u < p and pow((u**3 + 486662 * u * u + u) % p, (p - 1) // 2, p) == 1:
        break
x, z = ladder(8, u)
u8 = x * pow(z, p - 2, p) % p
assert ladder(L, u8)[1] == 0 and z != 0  # prime order, not the identity
print("i =", i)
print(list(u8.to_bytes(32, "little")))
