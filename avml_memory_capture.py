#!/usr/bin/env python3

# Script: avml_memory_capture.py
# Purpose: Acquire volatile memory using AVML for Palo XSIAM Action Center
# Date: April 03, 2025
# Description: This script uses AVML to get a memory dump and system.map from a Linux host to use with Volatility. The script has debug level logging of actions take for forensic timestamp purposes to preserve chain of custody.
# Timeout: 1200
# Input: Run by entry point: Main
# Output: Auto Detect or String
# Logs: /var/log/avml_script_hostname.log
# Final log to hash the Log file: /var/log/avml_script_hostname_final.log
# Dump: /var/dump/avml/memory_dump_hostname_datetimestamp
# System.map(Used for Volatility): /var/dump/avml/System.map-hostname
# Environment: Bare Metal, VM, AWS, GCP, Azure

import subprocess
import hashlib
import os
import sys
import traceback
from datetime import datetime
import time
import shutil

# AVML Configuration
AVML_VERSION = "v0.13.0"  # Update as needed
AVML_URL = f"https://github.com/microsoft/avml/releases/download/{AVML_VERSION}/avml"
TEMP_AVML = "/tmp/avml"

# Get hostname once at startup
HOSTNAME = os.uname().nodename

def log(message, error=False, log_file=f"/var/log/avml_script_{HOSTNAME}.log"):
    """Log messages to stdout/stderr and a file."""
    stream = sys.stderr if error else sys.stdout
    print(message, file=stream)
    with open(log_file, "a") as f:
        print(f"{datetime.now()}: {'ERROR' if error else 'INFO'}: {message}", file=f)

def check_disk_space(path, required_mb, hostname=HOSTNAME):
    """Check if there’s enough disk space (in MB) at the given path."""
    log(f"Checking disk space at {path}")
    statvfs = os.statvfs(path)
    free_bytes = statvfs.f_bavail * statvfs.f_frsize
    free_mb = free_bytes / (1024 * 1024)
    if free_mb < required_mb:
        raise Exception(f"Insufficient disk space at {path}: {free_mb:.2f} MB available, {required_mb:.2f} MB required")
    log(f"INFO: Disk space check at {path}: {free_mb:.2f} MB available, {required_mb:.2f} MB required")

def download_avml(hostname=HOSTNAME):
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
        log(f"DEBUG: wget stdout: {result.stdout}")
        log(f"DEBUG: wget stderr: {result.stderr}")
        
        os.chmod(TEMP_AVML, 0o700)
        log(f"INFO: AVML downloaded and made executable at {TEMP_AVML}")
        return TEMP_AVML
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else f"Command failed with exit code {e.returncode}, stdout: {e.stdout}"
        raise Exception(f"Failed to download AVML: {error_msg}")
    except Exception as e:
        raise Exception(f"Error downloading AVML: {str(e)}")

def capture_memory_dump(avml_path, output_dir, timeout=900, hostname=HOSTNAME):
    """Capture memory dump locally using AVML with configurable timeout."""
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_file = os.path.join(output_dir, f"memory_dump_{hostname}_{timestamp}")
    
    log(f"Capturing memory dump to {dump_file} with timeout {timeout} seconds")
    command = [avml_path, dump_file]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        end_time = time.time()
        log(f"INFO: Memory dump captured successfully at {dump_file} in {end_time - start_time:.2f} seconds")
        log(f"DEBUG: AVML stdout: {result.stdout}")
        log(f"DEBUG: AVML stderr: {result.stderr}")
        return dump_file
    except subprocess.TimeoutExpired:
        end_time = time.time()
        log(f"ERROR: Memory dump timed out after {timeout} seconds (elapsed: {end_time - start_time:.2f} seconds)", error=True)
        raise Exception(f"Memory dump timed out after {timeout} seconds")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else f"Command failed with exit code {e.returncode}, stdout: {e.stdout}"
        raise Exception(f"Failed to capture memory dump: {error_msg}")
    except Exception as e:
        raise Exception(f"Error during memory dump: {str(e)}")
    finally:
        if os.path.exists(avml_path):
            os.remove(avml_path)
            log(f"INFO: Cleaned up AVML binary at {avml_path}")

def verify_file_integrity(file_path, file_type="file", hostname=HOSTNAME):
    """Verify the integrity of a file using SHA-256 with chunked reading."""
    start_time = time.time()
    log(f"Verifying integrity of {file_type} {file_path} using SHA-256")
    try:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"{file_type.capitalize()} not found at {file_path}")
        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"No read permission for {file_path}")
        
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        sha256_hash = sha256.hexdigest()
        end_time = time.time()
        log(f"INFO: SHA-256 checksum of {file_type} {file_path}: {sha256_hash} calculated in {end_time - start_time:.2f} seconds")
        return sha256_hash
    except FileNotFoundError as e:
        raise Exception(f"Failed to verify {file_type} integrity: {str(e)}")
    except PermissionError as e:
        raise Exception(f"Failed to verify {file_type} integrity: {str(e)}")
    except MemoryError:
        raise Exception(f"Failed to verify {file_type} integrity: Out of memory while reading {file_path}")
    except IOError as e:
        raise Exception(f"Failed to verify {file_type} integrity: I/O error - {str(e)}")
    except Exception as e:
        raise Exception(f"Failed to verify {file_type} integrity: Unknown error - {traceback.format_exc()}")

def copy_system_map(output_dir, hostname=HOSTNAME):
    """Copy System.map file if available and compute its SHA-256 hash."""
    kernel_version = os.uname().release
    system_map_src = f"/boot/System.map-{kernel_version}"
    system_map_dst = os.path.join(output_dir, f"System.map-{kernel_version}_{hostname}")
    
    if os.path.exists(system_map_src):
        system_map_hash = verify_file_integrity(system_map_src, "System.map")
        shutil.copy2(system_map_src, system_map_dst)
        log(f"INFO: Copied {system_map_src} to {system_map_dst}")
        return system_map_dst, system_map_hash
    else:
        log(f"WARNING: System.map not found at {system_map_src}", error=True)
        return None, None

def create_final_log(main_log_file, hostname=HOSTNAME):
    """Create a final log file with the SHA-256 hash of the main log file."""
    final_log_file = f"/var/log/avml_script_{hostname}_final.log"
    log_hash = verify_file_integrity(main_log_file, "main log file")
    with open(final_log_file, "w") as f:
        f.write(f"{datetime.now()}: INFO: SHA-256 hash of {main_log_file}: {log_hash}\n")
    log(f"INFO: Created final log file {final_log_file} with SHA-256 hash of main log")

def main():
    start_time = time.time()
    main_log_file = f"/var/log/avml_script_{HOSTNAME}.log"
    log("Script execution started", log_file=main_log_file)
    log(f"Raw arguments received: {sys.argv}", log_file=main_log_file)
    log(f"Running kernel version: {os.uname().release}", log_file=main_log_file)

    if os.geteuid() != 0:
        sys.stderr.write("ERROR: Script must run with root permissions\n")
        return "error=Script must run with root permissions | status=failure"

    import argparse
    parser = argparse.ArgumentParser(description="Capture local memory dump using AVML")
    parser.add_argument("--output_dir", default="/var/dump/avml", help="Directory to save the memory dump")
    parser.add_argument("--timeout", type=int, default=900, help="Timeout in seconds for memory dump capture (default: 900)")
    
    try:
        args = parser.parse_args()
    except SystemExit as e:
        log(f"WARNING: Argument parsing failed with code {e.code}, using defaults", error=True, log_file=main_log_file)
        args = parser.parse_args([])
    
    output_dir = args.output_dir
    timeout = args.timeout
    log(f"Using output_dir: {output_dir}", log_file=main_log_file)
    log(f"Using timeout: {timeout} seconds", log_file=main_log_file)

    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            log(f"INFO: Created output directory: {output_dir}", log_file=main_log_file)

        avml_path = download_avml()
        
        memory_size_mb = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024 * 1024)
        log(f"INFO: Calculated memory size: {memory_size_mb:.2f} MB", log_file=main_log_file)
        total_required_mb = memory_size_mb + 200 + 10  # 200 MB buffer + 10 MB for System.map
        check_disk_space(output_dir, total_required_mb)
        
        dump_file = capture_memory_dump(avml_path, output_dir, timeout)
        dump_sha256_hash = verify_file_integrity(dump_file, "memory dump")
        system_map_file, system_map_hash = copy_system_map(output_dir)
        
        end_time = time.time()
        result = (
            f"dump_file={dump_file} | dump_sha256_hash={dump_sha256_hash} | "
            f"system_map={system_map_file or 'not_found'} | system_map_sha256_hash={system_map_hash or 'not_calculated'} | "
            f"status=success"
        )
        log(f"DEBUG: Final output: {result} (total time: {end_time - start_time:.2f} seconds)", log_file=main_log_file)
        create_final_log(main_log_file)  # Create final log with SHA-256 of main log
        return result
    except Exception as e:
        error_result = f"error={str(e)} | status=failure"
        log(f"DEBUG: Error output: {error_result}", error=True, log_file=main_log_file)
        create_final_log(main_log_file)  # Ensure final log is created even on failure
        return error_result
    finally:
        log("Script execution completed or interrupted", log_file=main_log_file)

if __name__ == "__main__":
    output = main()
    print(output)
