# Hikvision TFTP Recovery Tool (Python 3 Upgrade)

This project upgrades the original Hikvision TFTP Recovery Tool, which was written in Python 2, to Python 3. Python 2 is deprecated and no longer supported, so this updated version ensures compatibility with Python 3. The tool provides a script-based solution to recover or unbrick Hikvision devices using TFTP. It includes two main components:  
- **`start.sh`**: A Bash script to configure the network interface and execute the Python server.  
- **`hikvision_tftpd3.py`**: A Python 3 script implementing a minimal TFTP server to serve firmware files to Hikvision devices.

**Note**: This tool is specifically written for the **DS-7608NI-i2/8p NVR** model. Other models are not guaranteed to work and have not been tested.

---

## Files Overview

### `start.sh`

#### Purpose:
- Configures your system's network interface to the required IP address (`192.0.0.128`).
- Checks if the IP address is already assigned to avoid conflicts.
- Executes the TFTP server implemented in `hikvision_tftpd3.py`.
- Cleans up the network configuration after the script completes or is interrupted.

#### Features:
1. **Interface Detection**:
   - Automatically detects the first active Ethernet interface.
2. **IP Assignment**:
   - Sets the interface's IP address to `192.0.0.128` (required for Hikvision recovery mode).
   - Ensures the IP is not already assigned before attempting to configure it.
3. **Error Handling**:
   - Handles various errors like missing permissions or unavailable network interfaces gracefully.
4. **Cleanup**:
   - Automatically removes the assigned IP address after the script completes, even if terminated early (e.g., via `Ctrl+C`).

#### Usage:
```bash
sudo ./start.sh
```

#### Example Output:
```
Found Ethernet interface: eth0
Setting IP address of eth0 to 192.0.0.128...
Starting Python script...
Script completed successfully!
Cleaning up: Removing IP address 192.0.0.128 from eth0...
Done!
```

---

### `hikvision_tftpd3.py`

#### Purpose:
- Implements a minimal TFTP server to serve firmware files to Hikvision devices.

#### Features:
1. **TFTP Protocol**:
   - Supports TFTP's Read Request (RRQ) operation to send firmware files in response to client requests.
2. **Handshake Support**:
   - Responds to Hikvision-specific "magic" handshake packets to initiate the recovery process.
3. **Configurable Block Size**:
   - Automatically adjusts the TFTP block size based on client options for optimal performance.
4. **Error Handling**:
   - Provides detailed logs for unexpected packets or errors during the TFTP process.

#### Usage:
The script is typically executed by `start.sh`. However, it can also be run independently if the required network configuration is already in place:
```bash
python3 ./hikvision_tftpd3.py --server-ip 192.0.0.128
```

#### Command-Line Arguments:
- **`--filename`** (default: `digicap.dav`):
  The firmware file to serve via TFTP. Ensure the file is present in the same directory as the script.
- **`--server-ip`** (default: `192.0.0.128`):
  The IP address the TFTP server binds to. This must match the device's recovery expectations.

#### Example Output:
```
Setting block size to 512
Serving 102400-byte digicap.dav (block size 512, 200 blocks)
Replied to magic handshake request.
Starting transfer
  53:    5 /  200 [#####                     ]
  ...
  53:  200 /  200 [##########################]
  Done!
```

---

### Legacy Files: `hikvision_tftpd.py` and `hikvision_tftpd_test.py`

The files `hikvision_tftpd.py` and `hikvision_tftpd_test.py` are considered legacy and are provided for historical purposes. They were originally written for Python 2 and are not maintained or recommended for use in modern systems. Users are encouraged to use `hikvision_tftpd3.py` for Python 3 compatibility and better performance.

---

## Workflow

1. Run the **`start.sh`** script:
   - Configures the network interface.
   - Launches the TFTP server (`hikvision_tftpd3.py`).

2. The Hikvision device in recovery mode:
   - Sends a handshake packet to the server.
   - Initiates a TFTP transfer to retrieve the firmware file (`digicap.dav`).

3. After successful recovery:
   - The TFTP transfer completes.
   - The network configuration is cleaned up by the `start.sh` script.

---

## Prerequisites

- Linux environment with Bash and Python 3 installed.
- Administrative privileges (`sudo`) to configure the network interface.
- The firmware file (`digicap.dav`) present in the same directory as the scripts.

---

## Troubleshooting

### Common Issues:
1. **Permission Denied**:
   - Run the script with `sudo`.
2. **IP Address Already Assigned**:
   - The script will handle this gracefully, but ensure no conflicting services are running.
3. **Python Errors**:
   - Ensure Python 3 is installed and available as `python3`.

### Logs:
- Both scripts provide detailed logs to help diagnose issues. Check the output for clues if something goes wrong.

---

## Disclaimer

This tool is specifically written for the **DS-7608NI-i2/8p NVR** model. Other models may not work as intended, as they have not been tested.  
The tool is provided as-is under the MIT license. The authors are not responsible for any damage caused by improper use. Use at your own risk.
