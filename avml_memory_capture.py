#!/usr/bin/env python3

# Script: avml_memory_capture.py
# Purpose: Acquire volatile memory using AVML for Palo XSIAM Action Center
# Date: April 03, 2025
# Description: This script uses AVML to get a memory dump and system.map from a Linux host to use with Volatility. The script has debug level logging of actions taken for forensic timestamp purposes to preserve chain of custody.
# Timeout: 1200
# Input: Run by entry point: Main
# Output: Auto Detect or String
# Logs: /var/log/avml/avml_script_<hostname>.log
# Final log to hash the Log file: /var/log/avml/avml_final_hash_<hostname>.log
# Dump: /var/dump/avml/<hostname>_<timestamp>.lime
# System.map (Used for Volatility): /var/dump/avml/System.map-<kernel_version>_<hostname>
# Environment: Bare Metal, VM, AWS, GCP, Azure

import subprocess
import hashlib
import os
import sys
import traceback
from datetime import datetime
import time
import shutil
import argparse

# AVML Configuration
AVML_VERSION = "v0.13.0"
AVML_URL = f"https://github.com/microsoft/avml/releases/download/{AVML_VERSION}/avml"
TEMP_AVML = "/tmp/avml"

# Directories
DUMP_DIR = "/var/dump/avml"
LOG_DIR = "/var/log/avml"

# Get hostname
HOSTNAME = os.uname().nodename

def log(message, error=False):
    """Log messages to stdout/stderr and a file."""
    stream = sys.stderr if error else sys.stdout
    print(message, file=stream)
    
    # Ensure the log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)
    
    log_file_path = os.path.join(LOG_DIR, f"avml_script_{HOSTNAME}.log")
    with open(log_file_path, "a") as f:
        print(f"{datetime.now()}: {'ERROR' if error else 'INFO'}: {message}", file=f)

def compute_sha256(file_path, silent=False):
    """Compute SHA-256 hash of a file with error handling, optionally suppressing logs."""
    start_time = time.time()
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        sha256_hash = sha256.hexdigest()
        end_time = time.time()
        if not silent:
            log(f"Verifying integrity of file {file_path} using SHA-256")
            log(f"SHA-256 checksum of file {file_path}: {sha256_hash} calculated in {end_time - start_time:.2f} seconds")
        return sha256_hash
    except Exception as e:
        log(f"Failed to compute SHA-256 for {file_path}: {str(e)}", error=True)
        return None

def cleanup_avml_binary(avml_path):
    """Clean up the AVML binary to prevent misuse."""
    try:
        if os.path.exists(avml_path):
            os.remove(avml_path)
            log(f"Cleaned up AVML binary at {avml_path}")
    except Exception as e:
        log(f"Failed to clean up AVML binary: {str(e)}", error=True)

def check_disk_space(path, required_mb):
    """Check if there’s enough disk space (in MB) at the given path."""
    log(f"Checking disk space at {path}")
    statvfs = os.statvfs(path)
    free_bytes = statvfs.f_bavail * statvfs.f_frsize
    free_mb = free_bytes / (1024 * 1024)
    if free_mb < required_mb:
        raise Exception(f"Insufficient disk space at {path}: {free_mb:.2f} MB available, {required_mb:.2f} MB required")
    log(f"Disk space check at {path}: {free_mb:.2f} MB available, {required_mb:.2f} MB required")

def download_avml():
    """Download AVML binary using wget."""
    log(f"Downloading AVML from {AVML_URL}")
    try:
        if not os.access("/tmp", os.W_OK):
            raise Exception("No write permission to /tmp")
        result = subprocess.run(
            ["wget", "-q", AVML_URL, "-O", TEMP_AVML],
            capture_output=True,
            text=True,
            check=True
        )
        log(f"wget stdout: {result.stdout}")
        log(f"wget stderr: {result.stderr}")
        
        os.chmod(TEMP_AVML, 0o700)
        log(f"AVML downloaded and made executable at {TEMP_AVML}")
        return TEMP_AVML
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else f"Command failed with exit code {e.returncode}, stdout: {e.stdout}"
        raise Exception(f"Failed to download AVML: {error_msg}")
    except Exception as e:
        raise Exception(f"Error downloading AVML: {str(e)}")

def capture_memory_dump(avml_path, output_dir, timeout=1200):
    """Capture memory dump locally using AVML with configurable timeout."""
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_file = os.path.join(output_dir, f"{HOSTNAME}_{timestamp}.lime")
    
    command = [avml_path, dump_file]
    log(f"Running AVML command: {' '.join(command)}")
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        end_time = time.time()
        log(f"Memory dump captured successfully at {dump_file} in {end_time - start_time:.2f} seconds")
        log(f"AVML stdout: {result.stdout}")
        log(f"AVML stderr: {result.stderr}")
        return dump_file
    except subprocess.TimeoutExpired:
        end_time = time.time()
        log(f"Memory dump timed out after {timeout} seconds (elapsed: {end_time - start_time:.2f} seconds)", error=True)
        raise Exception(f"Memory dump timed out after {timeout} seconds")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else f"Command failed with exit code {e.returncode}, stdout: {e.stdout}"
        log(f"AVML command failed: {error_msg}", error=True)
        raise Exception(f"Failed to capture memory dump: {error_msg}")
    except Exception as e:
        log(f"Error during memory dump: {str(e)}", error=True)
        raise Exception(f"Error during memory dump: {str(e)}")

def verify_file_integrity(file_path, file_type="file"):
    """Verify the integrity of a file using SHA-256 with chunked reading."""
    return compute_sha256(file_path, silent=False)

def copy_system_map(output_dir):
    """Copy System.map file if available and compute its SHA-256 hash."""
    kernel_version = os.uname().release
    system_map_src = f"/boot/System.map-{kernel_version}"
    system_map_dst = os.path.join(output_dir, f"System.map-{kernel_version}_{HOSTNAME}")
    
    if os.path.exists(system_map_src):
        system_map_hash = verify_file_integrity(system_map_src, "System.map")
        shutil.copy2(system_map_src, system_map_dst)
        log(f"Copied {system_map_src} to {system_map_dst}")
        return system_map_dst, system_map_hash
    else:
        log(f"System.map not found at {system_map_src}", error=True)
        return None, None

def create_final_log(main_log_file):
    """Create a final log file with the SHA-256 hash of the main log file."""
    final_log_file = os.path.join(LOG_DIR, f"avml_final_hash_{HOSTNAME}.log")
    start_time = time.time()
    log_hash = compute_sha256(main_log_file, silent=True)
    end_time = time.time()
    if log_hash:
        with open(final_log_file, "w") as f:
            f.write(f"Verifying integrity of main log file {main_log_file} using SHA-256\n")
            f.write(f"SHA-256 checksum of main log file {main_log_file}: {log_hash} calculated in {end_time - start_time:.2f} seconds\n")
            f.write(f"log_file={main_log_file} | log_sha256_hash={log_hash}\n")
    else:
        log(f"Failed to compute hash for main log file {main_log_file}", error=True)

def main():
    start_time = time.time()
    main_log_file = os.path.join(LOG_DIR, f"avml_script_{HOSTNAME}.log")
    log("Script execution started")
    log(f"Raw arguments received: {sys.argv}")
    log(f"Running kernel version: {os.uname().release}")

    if os.geteuid() != 0:
        sys.stderr.write("ERROR: Script must run with root permissions\n")
        return "error=Script must run with root permissions | status=failure"

    parser = argparse.ArgumentParser(description="Capture local memory dump using AVML")
    parser.add_argument("--output_dir", default="/var/dump/avml", help="Directory to save the memory dump")
    parser.add_argument("--timeout", type=int, default=1200, help="Timeout in seconds for memory dump capture")
    try:
        args = parser.parse_args()
    except SystemExit as e:
        log(f"Argument parsing failed with code {e.code}, using defaults", error=True)
        args = parser.parse_args([])

    output_dir = args.output_dir
    timeout = args.timeout
    log(f"Using output_dir: {output_dir}")
    log(f"Using timeout: {timeout} seconds")
    avml_path = None

    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            log(f"Created output directory: {output_dir}")

        avml_path = download_avml()
        
        memory_size_mb = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024 * 1024)
        log(f"Calculated memory size: {memory_size_mb:.2f} MB")
        total_required_mb = memory_size_mb + 200 + 10
        check_disk_space(output_dir, total_required_mb)
        
        dump_file = capture_memory_dump(avml_path, output_dir, timeout)
        dump_sha256_hash = verify_file_integrity(dump_file, "memory dump")
        system_map_file, system_map_hash = copy_system_map(output_dir)
        
        # Clean up AVML binary after verification
        cleanup_avml_binary(avml_path)
        avml_path = None
        
        end_time = time.time()
        result = (
            f"dump_file={dump_file} | dump_sha256_hash={dump_sha256_hash} | "
            f"system_map={system_map_file or 'not_found'} | system_map_sha256_hash={system_map_hash or 'not_calculated'} | "
            f"status=success"
        )
        log(f"Final output: {result} (total time: {end_time - start_time:.2f} seconds)")
        create_final_log(main_log_file)
        return result
    except Exception as e:
        error_result = f"error={str(e)} | status=failure"
        log(f"Error output: {error_result}", error=True)
        create_final_log(main_log_file)
        return error_result
    finally:
        # Ensure AVML binary is cleaned up even if an error occurs
        if avml_path and os.path.exists(avml_path):
            cleanup_avml_binary(avml_path)
        log("Script execution completed or interrupted")

if __name__ == "__main__":
    output = main()
    print(output)
