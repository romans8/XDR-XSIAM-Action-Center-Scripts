AVML Memory Capture Scripts

Overview
These scripts utilize the AVML (Azure Volatility Memory Library) to capture volatile memory dumps and System.map files from Linux hosts for forensic analysis with tools like Volatility. Designed for the Palo XSIAM Action Center, they provide robust logging for forensic timestamping to preserve chain of custody.
Scripts

avml_memory_capture.py: Captures memory dumps locally on the host.
azure_avml_memory_capture.py: Captures memory dumps with the option to upload to an Azure Blob Storage URL, falling back to local capture if authentication fails.

Features

Verbose Logging: Detailed logs with timestamps for forensic purposes, ensuring chain of custody.
Flexible Output: Memory dumps saved as .lime files, compatible with Volatility.
System.map Support: Copies the System.map file for kernel analysis.
Environment Support: Runs on Bare Metal, VMs, AWS, GCP, and Azure.
Timeout Configuration: Configurable timeout (default: 1200 seconds for local, 900 seconds for Azure).
Secure Handling: Sanitizes sensitive Azure SAS URLs in logs and cleans up the AVML binary after use to prevent misuse.

Prerequisites

Operating System: Linux (tested on Ubuntu, CentOS, etc.)
Python: Version 3.6 or higher - If not running in Action Center
Dependencies:
wget (for downloading AVML)
Root privileges (required for memory capture) - If not running in action center


Azure Script Only:
Azure Blob Storage account with a valid SAS URL (optional for upload)



Installation

Clone the Repository:
git clone https://github.com/yourusername/avml-capture.git
cd avml-capture


Ensure Dependencies:Install wget if not already present:
sudo apt-get install wget  # For Debian/Ubuntu
sudo yum install wget     # For CentOS/RHEL


Verify Python Version:
python3 --version

Ensure Python 3.6 or higher is installed.


Usage
Local Capture (avml_memory_capture.py)
Captures a memory dump and System.map file locally.
sudo python3 avml_memory_capture.py --output_dir /var/dump/avml --timeout 1200

Arguments:

--output_dir: Directory to save the memory dump and System.map (default: /var/dump/avml)
--timeout: Timeout in seconds for memory capture (default: 1200)

Example Output:
/var/dump/avml/myhost_20250502_123456.lime
/var/dump/avml/System.map-5.15.0-73-generic_myhost

Azure Capture (azure_avml_memory_capture.py)
Captures a memory dump with optional upload to Azure Blob Storage, falling back to local capture if the upload fails.
sudo python3 azure_avml_memory_capture.py --sas_url "<your_sas_url>"

Arguments:

--sas_url: SAS URL for Azure Blob Storage upload (optional; if omitted, captures locally)

Example Output:
/var/dump/avml/myhost_20250502_123456.lime
/var/dump/avml/System.map-5.15.0-73-generic_myhost

File Locations



File Type
Location
Description



Main Log
/var/log/avml/avml_script_<hostname>.log
Detailed forensic logs with timestamps


Final Hash Log
/var/log/avml/avml_final_hash_<hostname>.log
SHA-256 hash of the main log file


Memory Dump
/var/dump/avml/<hostname>_<timestamp>.lime
Memory dump in LiME format for Volatility


System.map
/var/dump/avml/System.map-<kernel_version>_<hostname>
Kernel symbol map for Volatility analysis


Log Examples
Main Log (/var/log/avml/avml_script_myhost.log):
2025-05-02 12:34:56.123456: INFO: Script execution started
2025-05-02 12:34:56.123789: INFO: Running kernel version: 5.15.0-73-generic
2025-05-02 12:34:56.124012: INFO: Created output directory: /var/dump/avml
...
2025-05-02 12:35:10.456789: INFO: Memory dump captured successfully at /var/dump/avml/myhost_20250502_123456.lime in 14.33 seconds
2025-05-02 12:35:10.457012: INFO: Copied /boot/System.map-5.15.0-73-generic to /var/dump/avml/System.map-5.15.0-73-generic_myhost

Final Hash Log (/var/log/avml/avml_final_hash_myhost.log):
Verifying integrity of main log file /var/log/avml/avml_script_myhost.log using SHA-256
SHA-256 checksum of main log file /var/log/avml/avml_script_myhost.log: 17f4320f9486fa13360d0fc2697db43065405eda3bd601eff8e3fd4cf682fdbc calculated in 0.00 seconds
log_file=/var/log/avml/avml_script_myhost.log | log_sha256_hash=17f4320f9486fa13360d0fc2697db43065405eda3bd601eff8e3fd4cf682fdbc

Environment Support

Bare Metal: Tested on physical Linux servers.
Virtual Machines: Compatible with VMware, VirtualBox, etc.
Cloud: Fully supported on AWS, GCP, and Azure.

Troubleshooting

Permission Errors:

Ensure the script is run with sudo to access memory and write to /var/dump/avml and /var/log/avml.
Check directory permissions:sudo chmod -R u+rw /var/dump/avml /var/log/avml




AVML Download Fails:

Verify wget is installed and internet connectivity is available.
Check the AVML URL and version in the script.


Timeout Issues:

Increase the --timeout value if the memory capture exceeds 1200 seconds (local) or 900 seconds (Azure).


Log File Issues:

If /var/log/avml/avml_final_hash_<hostname>.log is missing, check for errors in /var/log/avml/avml_script_<hostname>.log.
Ensure sufficient disk space:df -h /var





Contributing
Contributions are welcome! Please submit a pull request or open an issue on GitHub to suggest improvements or report bugs.

Fork the repository.
Create a new branch: git checkout -b feature/your-feature.
Commit your changes: git commit -m "Add your feature".
Push to the branch: git push origin feature/your-feature.
Open a pull request.

License
This project is licensed under the MIT License.
Acknowledgments

Microsoft AVML for providing the memory capture tool.
Volatility Foundation for forensic analysis tools.
Palo XSIAM Action Center for inspiring this project.


Maintained by [Romans 6]Last updated: May 2025
