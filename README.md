# Traffic Analysis Scripts
This repository contains a collection of scripts that I have created for various Forensic projects . Each script is designed to perform a specific task and can be used independently or integrated into other projects.

## snort_monitor.py

The script loads Snort rules from a specified file and monitors network traffic for potential intrusion attempts. It then collects and analyzes alerts generated by Snort during the monitoring process.

#### Prerequisites

Before running the script, make sure you have the following:

- Python installed on your system (Python 3.x recommended).
- `pysnort` library installed. You can install it using `pip`:

#### Usage

Replace `"path/to/file.rules"` with the actual path to your Snort rules file.

To run it :
```bash
python3 snort_monitor.py
```

Ensure that you have the necessary permissions to run Snort and access the network interfaces.
