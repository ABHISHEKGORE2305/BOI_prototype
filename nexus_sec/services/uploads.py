# services/uploads.py
#
# Streaming APK uploads to disk with size and format checks.

import hashlib
import os

from fastapi import HTTPException

# APKs are ZIP archives
ZIP_MAGIC = b"PK\x03\x04"
CHUNK_SIZE = 1024 * 1024


def remove_file(path):
    try:
        os.remove(path)
    except OSError:
        pass


def save_upload(source, destination, max_bytes):
    """Stream an upload to disk, enforcing size and APK (ZIP) format.

    Returns the file's SHA-256 hex digest.
    """

    digest = hashlib.sha256()
    written = 0
    with open(destination, "wb") as buffer:
        while chunk := source.read(CHUNK_SIZE):
            if written == 0 and not chunk.startswith(ZIP_MAGIC):
                raise HTTPException(
                    status_code=400,
                    detail="File is not a valid APK (ZIP) archive"
                )
            written += len(chunk)
            if written > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds {max_bytes // (1024 * 1024)} MB limit"
                )
            digest.update(chunk)
            buffer.write(chunk)

    if written == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    return digest.hexdigest()
