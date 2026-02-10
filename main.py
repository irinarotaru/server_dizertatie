from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import base64
import os
import uvicorn
import io
import numpy as np
from PIL import Image
from Pyfhel import Pyfhel, PyCtxt, PyPtxt
import pickle

app = FastAPI()

PHOTO_DIR = "photos"
os.makedirs(PHOTO_DIR, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
def index():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Camera Capture</title>
    <style>
        body { text-align: center; font-family: sans-serif; }
        video { border: 2px solid black; border-radius: 8px; }
        button { margin-top: 20px; padding: 10px 20px; font-size: 16px; cursor: pointer; }
    </style>
</head>
<body>
    <h2>Camera Capture</h2>
    <p>Press the button to take a photo</p>

    <video id="video" width="480" autoplay playsinline></video>
    <br>
    <button id="captureButton">Take Photo</button>

    <canvas id="canvas" width="480" height="360" style="display:none;"></canvas>

    <script>
        const video = document.getElementById("video");
        const canvas = document.getElementById("canvas");
        const button = document.getElementById("captureButton");

        async function startCamera() {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ video: true });
                video.srcObject = stream;
            } catch (err) {
                alert("Could not access camera: " + err);
            }
        }

        button.addEventListener("click", async () => {
            // Ask user for photo name
            let name = prompt("Please enter your name:");
            if (!name) {
                alert("Your name is required");
                return;
            }
            name = name.trim();

            // Draw video frame to canvas
            const ctx = canvas.getContext("2d");
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

            const imageData = canvas.toDataURL("image/png");

            try {
                const response = await fetch("/photo", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ image: imageData, filename: name })
                });

                const result = await response.json();
                alert("Photo saved as: " + result.filename);
            } catch (err) {
                alert("Failed to save photo: " + err);
            }
        });

        startCamera();
    </script>
</body>
</html>
    """

def encrypt_image_to_file(image_bytes, folder_path, filename):
    os.makedirs(folder_path, exist_ok=True)
    img = Image.open(io.BytesIO(image_bytes)).convert('L')
    img_array = np.array(img, dtype=np.int64)
    width, height = img.size
    flattened_pixels = img_array.flatten()

    HE = Pyfhel()
    HE.contextGen(scheme='bfv', n=8192, t=65537)
    HE.keyGen()

    n_slots = HE.n
    all_ciphertexts_serialized = []

    print(f"Encrypting...")
    for i in range(0, len(flattened_pixels), n_slots):
        chunk = flattened_pixels[i: i + n_slots]
        if len(chunk) < n_slots:
            chunk = np.pad(chunk, (0, n_slots - len(chunk)))

        ptxt = HE.encodeInt(chunk)
        ctxt = HE.encrypt(ptxt)
        all_ciphertexts_serialized.append(ctxt.to_bytes())

    test_ptxt = HE.decrypt(ctxt)  # Decrypt the last batch created
    print(f"Verification - Last batch tail: {HE.decodeInt(test_ptxt)[-5:]}")

    data_to_save = {
        "context": HE.to_bytes_context(),
        "public_key": HE.to_bytes_public_key(),
        "secret_key": HE.to_bytes_secret_key(),
        "ciphertexts": all_ciphertexts_serialized,
        "metadata": {"width": width, "height": height}
    }

    full_path = os.path.join(folder_path, filename)
    with open(full_path, "wb") as f:
        pickle.dump(data_to_save, f)
    print(f"Encrypted file saved to {full_path}")


def decrypt_file_to_png(input_filepath, output_png_path):
    with open(input_filepath, "rb") as f:
        data = pickle.load(f)

    HE = Pyfhel()
    HE.from_bytes_context(data["context"])
    HE.from_bytes_public_key(data["public_key"])
    HE.from_bytes_secret_key(data["secret_key"])

    width, height = data["metadata"]["width"], data["metadata"]["height"]
    decrypted_flattened = []

    print(f"Decrypting batches...")
    for c_bytes in data["ciphertexts"]:
        # 1. Load Ciphertext
        ctxt = PyCtxt(pyfhel=HE, bytestring=c_bytes)

        # 2. Create an empty Plaintext object explicitly
        ptxt = PyPtxt(pyfhel=HE)

        # 3. Decrypt INTO the ptxt object
        HE.decrypt(ctxt, ptxt)

        # 4. Decode the ptxt object
        decrypted_chunk = HE.decodeInt(ptxt)
        decrypted_flattened.extend(decrypted_chunk)

    # Reconstruct Image
    total_pixels = width * height
    final_pixels = np.array(decrypted_flattened[:total_pixels], dtype=np.int64)
    final_pixels = np.clip(final_pixels, 0, 255).astype(np.uint8)
    final_img_array = final_pixels.reshape((height, width))

    Image.fromarray(final_img_array).save(output_png_path)
    print(f"Success! Image restored to {output_png_path}")


@app.post("/photo")
async def save_photo(request: Request):
    data = await request.json()
    image_base64 = data["image"].split(",")[1]  # Remove header
    image_bytes = base64.b64decode(image_base64)

    # Use the user-provided name
    filename = data["filename"].strip()
    encrypt_image_to_file(image_bytes, "encrypted_data", filename+".bin")
    #encrypt_to_single_file(image_bytes, "encrypted_data", filename+"1.bin")
    decrypt_file_to_png(f"encrypted_data/{filename}.bin", "restored.png")

"""
    if not filename.endswith(".png"):
        filename += ".png"

    # Sanitize filename to avoid directory issues
    filename = filename.replace("/", "_").replace("\\", "_")

    filepath = os.path.join(PHOTO_DIR, filename)

    with open(filepath, "wb") as f:
        f.write(image_bytes)

    return JSONResponse({"filename": filename})
    """

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000)
