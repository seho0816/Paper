import zipfile
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Constants for CWE-400/770 (Resource Consumption) limits
MAX_UNCOMPRESSED_SIZE_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB
MAX_FILES = 1000

def save_archive_to_temp(archive):
    temp_path = "/tmp/archive.zip"
    archive.save(temp_path)
    return temp_path

@app.route("/archive/upload", methods=["POST"])
def upload_archive():
    archive = request.files["archive"]
    archive_path = save_archive_to_temp(archive)

    extract_to_path = "/tmp/extracted"
    os.makedirs(extract_to_path, exist_ok=True)
    
    # Get the absolute, canonical path for the extraction target, ending with os.sep
    # This is crucial for robust path traversal checks (CWE-22)
    abs_extract_path = os.path.abspath(extract_to_path) + os.sep

    try:
        with zipfile.ZipFile(archive_path) as zf:
            # CWE-400/770: Check resource limits (uncompressed size, number of files) before extraction
            total_uncompressed_size = 0
            num_files = 0
            for member_info in zf.infolist():
                total_uncompressed_size += member_info.file_size
                num_files += 1

                if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE_BYTES:
                    return jsonify({"error": "Archive too large (uncompressed size)", "limit": f"{MAX_UNCOMPRESSED_SIZE_BYTES / (1024*1024*1024)}GB"}), 400
                if num_files > MAX_FILES:
                    return jsonify({"error": "Archive contains too many files", "limit": MAX_FILES}), 400

            # CWE-22: Iterate and extract each member safely, preventing path traversal
            for member in zf.namelist():
                # Skip directories for direct extraction, as parent directory creation handles them
                if member.endswith('/'):
                    continue

                # Construct the full path where this member would be extracted
                # Use os.path.join for platform independence
                # Normalize the path to handle potential relative paths within the zip (e.g., "dir/../file")
                member_target_path = os.path.join(extract_to_path, member)
                abs_member_target_path = os.path.abspath(member_target_path)

                # CWE-22: Path Traversal Check
                # Ensure the extracted file's absolute path is strictly within the target directory.
                # 'startswith' with 'os.sep' is a robust way to prevent escaping the directory.
                if not abs_member_target_path.startswith(abs_extract_path):
                    # This member tries to extract outside the designated directory
                    return jsonify({"error": f"Path traversal attempt detected for {member}"}), 400
                
                # Create parent directories for the file if they don't exist
                os.makedirs(os.path.dirname(abs_member_target_path), exist_ok=True)

                # Extract the file content using zf.open() for individual control
                try:
                    with zf.open(member) as source, open(abs_member_target_path, "wb") as target:
                        while True:
                            chunk = source.read(8192) # Read in chunks to prevent large memory consumption
                            if not chunk:
                                break
                            target.write(chunk)
                except Exception as e:
                    # Handle potential errors during file extraction (e.g., corrupted entry)
                    return jsonify({"error": f"Error extracting file {member}: {str(e)}"}), 500

    except zipfile.BadZipFile:
        return jsonify({"error": "Uploaded file is not a valid zip archive"}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

    return jsonify({"message": "done"})
