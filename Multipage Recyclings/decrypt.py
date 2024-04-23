from pwn import *

def blockify(message, size):
    return [message[i:i + size] for i in range(0, len(message), size)]

# Block the ciphertext
ct = bytes.fromhex("b25bc89662197c6462188e5960eea4fbef11424b8ebdcd6b45c8f4240d64f5d1981aab0e299ff75ce9fba3d5d78926543e5e8c262b81090aef60518ee241ab131db902d2582a36618f3b9a85a35f52352d5499861b4a878fac1380f520fe13deb1ca50c64f30e98fa6fdc070d02e148f")
ct_blocks = blockify(ct, 16)

# Leak
r = bytes.fromhex("5fe633e7071e690fbe58a9dace6f3606")
r_plus_1 = bytes.fromhex("501ccdc4600bc2dcf350c6b77fcf2681")

# Xor - leak to ciphertext
pt_block3 = xor(ct_blocks[4], r)
pt_block4 = xor(ct_blocks[5], r_plus_1)
plaintext = pt_block3 + pt_block4
print(plaintext)
