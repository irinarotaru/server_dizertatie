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


@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>FHE Face Capture</title>
        <style>
            body { text-align: center; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f4f9; }
            .camera-container { 
                position: relative; 
                display: inline-block; 
                margin-top: 20px;
                border: 5px solid #333;
                border-radius: 12px;
                overflow: hidden;
            }
            video { display: block; }

            /* Visual guide updated for 37:50 ratio (Portrait).
               Using 74x100 for a tighter "zoom" so you can stand closer.
            */
            #overlay {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 111px;  
                height: 150px; 
                border: 3px dashed #00FF00;
                box-shadow: 0 0 0 9999px rgba(0, 0, 0, 0.6); 
                pointer-events: none;
            }
            button { 
                margin-top: 20px; 
                padding: 12px 24px; 
                font-size: 18px; 
                background: #28a745; 
                color: white; 
                border: none; 
                border-radius: 5px; 
                cursor: pointer; 
            }
            button:hover { background: #218838; }
        </style>
    </head>
    <body>
        <h2>Secure Face Enrollment</h2>
        <p>Align your face within the green box (Stand Close)</p>

        <div class="camera-container">
            <video id="video" width="480" height="360" autoplay playsinline></video>
            <div id="overlay"></div>
        </div>
        <br>
        <button id="captureButton">Enroll Face</button>

        <canvas id="canvas" width="37" height="50" style="display:none;"></canvas>

        <script>
            const video = document.getElementById("video");
            const canvas = document.getElementById("canvas");
            const button = document.getElementById("captureButton");

            async function startCamera() {
                try {
                    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
                    video.srcObject = stream;
                } catch (err) {
                    alert("Camera access denied: " + err);
                }
            }

            button.addEventListener("click", async () => {
            // 1. IMMEDIATELY capture the frame from the video
            const ctx = canvas.getContext("2d");
            const cropW = 111; // Using the "Middle Ground" zoom for ease of use
            const cropH = 150;
            const sourceX = (video.videoWidth / 2) - (cropW / 2);
            const sourceY = (video.videoHeight / 2) - (cropH / 2);
        
            ctx.drawImage(
                video, 
                sourceX, sourceY, cropW, cropH, 
                0, 0, 37, 50
            );
        
            // 2. Convert to data URL immediately so the "moment" is saved
            const imageData = canvas.toDataURL("image/png");
        
            // 3. NOW ask for the name (the photo is already safely in memory)
            let name = prompt("Photo captured! Now, enter your name to save:");
            if (!name) {
                alert("Save cancelled. No name provided.");
                return;
            }
        
            // 4. Send the captured data to the server
            try {
                const response = await fetch("/photo", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ image: imageData, filename: name.trim() })
                });
        
                const result = await response.json();
                alert("Encrypted & Saved: " + result.filename);
            } catch (err) {
                alert("Error saving photo: " + err);
            }
        });
        
        startCamera();
        </script>
    </body>
    </html>
        """


def run_full_encrypted_flow(image_bytes, filename, folder_path="secure_vault"):
    # --- 1. SETUP & ENCRYPTION ---
    os.makedirs(folder_path, exist_ok=True)

    img = Image.open(io.BytesIO(image_bytes)).convert('L')
    width, height = img.size
    # Ensure memory is C-contiguous for Pyfhel/Cython
    flattened_pixels = np.ascontiguousarray(np.array(img).flatten(), dtype=np.int64)

    HE = Pyfhel()
    HE.contextGen(scheme='bfv', n=8192, t=65537)
    HE.keyGen()
    HE.relinKeyGen()

    n_slots = HE.n
    cipher_bytes_list = []

    print(f"Encrypting {len(flattened_pixels)} pixels...")
    for i in range(0, len(flattened_pixels), n_slots):
        chunk = flattened_pixels[i: i + n_slots]
        if len(chunk) < n_slots:
            chunk = np.pad(chunk, (0, n_slots - len(chunk)))

        ptxt = HE.encodeInt(chunk)
        ctxt = HE.encrypt(ptxt)
        cipher_bytes_list.append(ctxt.to_bytes())

    # Save everything to one file
    save_data = {
        "context": HE.to_bytes_context(),
        "public_key": HE.to_bytes_public_key(),
        "secret_key": HE.to_bytes_secret_key(),
        "relin_key": HE.to_bytes_relin_key(),
        "ciphertexts": cipher_bytes_list,
        "metadata": {"width": width, "height": height}
    }

    full_path = os.path.join(folder_path, filename+".bin")
    with open(full_path, "wb") as f:
        pickle.dump(save_data, f)

    print(f"Step 1 Complete: Encrypted file saved to {full_path}")

    # --- 2. LOADING & DECRYPTION ---
    print(f"Step 2: Loading and Decrypting...")
    with open(full_path, "rb") as f:
        loaded_data = pickle.load(f)

    # Re-setup HE from the loaded bytes
    new_HE = Pyfhel()
    new_HE.from_bytes_context(loaded_data["context"])
    new_HE.from_bytes_public_key(loaded_data["public_key"])
    new_HE.from_bytes_secret_key(loaded_data["secret_key"])

    decrypted_pixels = []
    for c_bytes in loaded_data["ciphertexts"]:
        ctxt = PyCtxt(pyfhel=new_HE, bytestring=c_bytes)

        # The 'Strict Wrapper' Fix:
        # Decrypt returns a raw array, we wrap it back into a ptxt to decode it
        raw_array = new_HE.decrypt(ctxt)
        tmp_ptxt = PyPtxt(pyfhel=new_HE)
        new_HE.encodeInt(raw_array, tmp_ptxt)

        decrypted_pixels.extend(new_HE.decodeInt(tmp_ptxt))

    # --- 3. RECONSTRUCT PNG ---
    w, h = loaded_data["metadata"]["width"], loaded_data["metadata"]["height"]
    final_array = np.array(decrypted_pixels[:w * h], dtype=np.int64)
    final_array = np.clip(final_array, 0, 255).astype(np.uint8)
    final_img = Image.fromarray(final_array.reshape((h, w)))

    os.makedirs("decrypted", exist_ok=True)
    output_path = "decrypted/"+filename+".png"
    final_img.save(output_path)
    print(f"Step 3 Complete: Decrypted image saved to {output_path}")


@app.post("/photo")
async def save_photo(request: Request):
    data = await request.json()
    image_base64 = data["image"].split(",")[1]  # Remove header
    image_bytes = base64.b64decode(image_base64)

    # Use the user-provided name
    filename = data["filename"].strip()
    run_full_encrypted_flow(image_bytes, filename=filename)

    return JSONResponse({"filename": filename})

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000)