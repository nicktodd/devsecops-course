"""
Python Dependency Risks — Vulnerable App

A simple Flask service that processes uploaded satellite imagery.
The functionality here is intentionally minimal — the demo focus is on the
packaging and dependency management, not on the application logic.

The same app.py appears in fixed/ unchanged; the security improvement is
entirely in requirements.txt (pinning + hashes) and the CI audit script.

Run:
    pip install -r requirements.txt
    python app.py
"""

import io

from flask import Flask, jsonify, request
from PIL import Image

app = Flask(__name__)

# Maximum accepted upload size (5 MB)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.route("/thumbnail", methods=["POST"])
def create_thumbnail():
    """Generate a 128x128 thumbnail from an uploaded satellite image."""
    if "image" not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    file = request.files["image"]

    try:
        img = Image.open(io.BytesIO(file.read()))
    except Exception:
        return jsonify({"error": "Invalid image file"}), 400

    original_size = img.size
    img.thumbnail((128, 128))

    buf = io.BytesIO()
    img.save(buf, format="PNG")

    return jsonify({
        "original_width":  original_size[0],
        "original_height": original_size[1],
        "thumbnail_width":  img.size[0],
        "thumbnail_height": img.size[1],
        "mode":            img.mode,
        "thumbnail_bytes": len(buf.getvalue()),
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False)
