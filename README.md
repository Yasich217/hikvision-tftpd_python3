# Hikvision TFTP Recovery Tool

This project provides a script-based solution to recover or unbrick Hikvision devices using TFTP. It includes two main components:  
- **`start.sh`**: A Bash script to configure the network interface and execute the Python server.  
- **`hikvision_tftpd3.py`**: A Python script implementing a minimal TFTP server to serve firmware files to Hikvision devices.

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
