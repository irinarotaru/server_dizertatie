import hashlib
import random
import os
import json


class ZKPKeyGenerator:
    def __init__(self, q):
        self.q = q

    def get_x(self, row, i):
        # Position-aware hashing ensures uniqueness across the file
        h = hashlib.sha256(i.to_bytes(4, 'big') + row).digest()
        return int.from_bytes(h, 'big') % self.q


# configuration
file_path = './secure_vault/sezi.bin'
file_size = os.path.getsize(file_path)

p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                     "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                     "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                     "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                     "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                     "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                     "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                     "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                     "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                     "DE2BCBF6955817183995497C1B844479099015974751C246"
                     "AD3225F823730B23690912E117B1812B", 16)
g = pow(2, 2, p)
q = (p - 1) // 2

gen = ZKPKeyGenerator(q)
public_keys = []
private_keys = []

with open(file_path, 'rb') as f:
    # wide table
    print(f"{'Offset':<8} | {'Hex':<12} | {'Raw Int':<10} | {'Bits':<35}")
    print("-" * 120)

    for _ in range(8):
        # Pick random position
        random_pos = random.randint(0, file_size - 4)
        f.seek(random_pos)
        four_bytes = f.read(4)

        # 1. Raw Data Calculations
        hex_val = four_bytes.hex(' ')
        raw_int = int.from_bytes(four_bytes, byteorder='big')
        bit_val = " ".join(f"{b:08b}" for b in four_bytes)

        # 2. ZKP Private Key Derivation
        private_key_x = gen.get_x(four_bytes, random_pos)
        private_keys.append(private_key_x)

        # Display - Truncating x for readability
        public_key_y = pow(g, private_key_x, p)
        public_keys.append(public_key_y)
        #print(public_key_y.bit_length()/8)

        print(f"{random_pos:<8} | {hex_val:<12} | {raw_int:<10} | {bit_val:<35}")


def save_keys(user, keys, filename, is_private=False):
    """Saves keys to a JSON file. Use is_private=True for Alice's secrets."""
    data = {user: [hex(k) for k in keys]}

    # Mode 'w' overwrites
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

    label = "PRIVATE SECRETS" if is_private else "PUBLIC KEYS"
    print(f"Saved {label} to {filename}")


# 1. Save Public Keys (For the Server)
save_keys("Alice", public_keys, "public_db.json")

# 2. Save Private Keys (For user only)
save_keys("Alice", private_keys, "alice_secrets.json", is_private=True)
