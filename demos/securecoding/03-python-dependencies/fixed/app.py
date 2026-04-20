"""
Python Dependency Risks — Fixed App (identical to vulnerable/app.py)

The application code is unchanged between vulnerable and fixed.
The entire security improvement is in packaging:
  - requirements.in  : human-maintained source constraints
  - requirements.txt : pip-compile lock file with exact versions + SHA-256 hashes
  - pip.conf         : restricts installation to an internal trusted mirror
  - audit.sh         : CI gate that fails the build on known CVEs

Run:
    pip install --require-hashes -r requirements.txt
    python app.py

The --require-hashes flag makes pip verify every downloaded package against
the sha256 hashes in requirements.txt, detecting tampering or substitution.
"""

import io

from flask import Flask, jsonify, request
from PIL import Image

app = Flask(__name__)

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
