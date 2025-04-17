import os
import sys
import hashlib

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read the file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError:
        sys.stderr.write(f"Cannot read file: {file_path}")
        return None
    except Exception as e:
        sys.stderr.write(f"Error calculating hash: {str(e)}")
        return None

def run(file_path):
    # Expand user and environment variables in path
    path = os.path.expanduser(file_path)
    path = os.path.expandvars(path)
    
    # Check if path is absolute
    if not os.path.isabs(path):
        sys.stderr.write(f"Input path <{path}> not valid, must be an absolute path")
        return None
    
    # Check if file exists
    if not os.path.exists(path):
        sys.stderr.write(f"File not found: {path}")
        return None
    
    # Calculate and return SHA256 hash
    file_hash = calculate_sha256(path)
    return file_hash
