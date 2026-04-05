import pickle
import numpy as np
import io
from PIL import Image
from Pyfhel import Pyfhel, PyCtxt


def compute_similarity(new_image_bytes, encrypted_file_path):
    with open(encrypted_file_path, "rb") as f:
        stored = pickle.load(f)

    # Load same context + public key
    HE = Pyfhel()
    HE.from_bytes_context(stored["context"])
    HE.from_bytes_public_key(stored["public_key"])
    HE.from_bytes_relin_key(stored["relin_key"])

    # Process query image
    img = Image.open(io.BytesIO(new_image_bytes)).convert('L')
    img = img.resize((stored["metadata"]["width"], stored["metadata"]["height"]))
    query_pixels = np.array(img).flatten().astype(np.int64)

    n_slots = HE.get_nSlots()
    cumulative_distance_ctxt = None

    print("Computing encrypted distance")

    for i, c_bytes in enumerate(stored["ciphertexts"]):
        ctxt_stored = PyCtxt(pyfhel=HE, bytestring=c_bytes)

        start = i * n_slots
        chunk = query_pixels[start:start + n_slots]

        if len(chunk) < n_slots:
            chunk = np.pad(chunk, (0, n_slots - len(chunk)))

        # Encode plaintext
        ptxt_query = HE.encodeInt(chunk)

        # Difference
        ctxt_diff = ctxt_stored - ptxt_query

        # Square
        ctxt_sq_diff = ctxt_diff * ctxt_diff
        HE.relinearize(ctxt_sq_diff)

        # Accumulate
        if cumulative_distance_ctxt is None:
            cumulative_distance_ctxt = ctxt_sq_diff
        else:
            cumulative_distance_ctxt += ctxt_sq_diff

    return HE, cumulative_distance_ctxt, stored["secret_key"]


def get_similarity_score(HE, distance_ctxt, secret_key_bytes):
    HE.from_bytes_secret_key(secret_key_bytes)

    decrypted = HE.decryptInt(distance_ctxt)

    # Convert mod t → signed integers
    t = HE.t
    decrypted = [(x if x < t//2 else x - t) for x in decrypted]

    return sum(decrypted)


def normalize_score(score, num_pixels):
    max_distance = num_pixels * (255 ** 2)
    similarity = 1 - (score / max_distance)
    return similarity


if __name__ == "__main__":
    VAULT_FILE = "./secure_vault/eui.bin"

    with open("./decrypted/eui6.png", "rb") as f:
        new_photo_data = f.read()

    he_obj, encrypted_dist, sk = compute_similarity(new_photo_data, VAULT_FILE)

    score = get_similarity_score(he_obj, encrypted_dist, sk)
    num_pixels = 50*37
    similarity = normalize_score(score, num_pixels)
    print(f"\nSimilarity Score (L2 Distance): {score}")
    print(f"Similarity is: {similarity}")