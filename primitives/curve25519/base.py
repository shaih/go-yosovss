# From supercop
# supercop-20210604/crypto_sign/ed25519/ref10/base.py
# with changes in the base

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def expmod(b, e, m):
    if e == 0: return 1
    t = expmod(b, e // 2, m) ** 2 % m
    if e & 1: t = (t * b) % m
    return t


def inv(x):
    return expmod(x, q - 2, q)


d = -121665 * inv(121666)
I = expmod(2, (q - 1) // 4, q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0: x = (x * I) % q
    if x % 2 != 0: x = q - x
    return x


def printbase(y: int):
    b = y.to_bytes(32, byteorder="little")
    for x in b:
        print(f"0x{x:02x}, ", end="")


# For base G
By = 4 * inv(5)
print("base G:")
printbase(By)

print()
print()

# we want our new point y for second generator for Pedersen, generated by main.py
By = 0x164af560f4bbc72c8761f6db325864e696c4c86e2c7e1e4fcbded121624f9edd
print("base H:")
printbase(By)