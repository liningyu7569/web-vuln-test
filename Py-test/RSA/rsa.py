import hashlib
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

USERNAME = "admin"
E = 65537
MESSAGE = "Welcome to LoveNote! Send encrypted love messages this Valentine's Day. Your communications are secured with industry-standard RSA-2048 digital signatures."

seed = f"{USERNAME}_lovenote_2026_valentine".encode()

# rebuild p and q
p = nextprime(int(hashlib.sha256(seed).hexdigest(), 16))
q = nextprime(int(hashlib.sha256(seed + b"pki").hexdigest(), 16))

n = p * q
phi = (p - 1) * (q - 1)
d = pow(E, -1, phi)

key = RSA.construct((n, E, d))

# RSA-PSS sign
h = SHA256.new(MESSAGE.encode())
modBits = key.size_in_bits()
emLen = (modBits - 1 + 7) // 8
maxSalt = emLen - h.digest_size - 2

signer = pss.new(key, salt_bytes=maxSalt)
signature = signer.sign(h)

print("username: admin")
print("message :", MESSAGE)
print("signature hex:")
print(signature.hex())