Hikvision TFTP Recovery Tool
This project provides a script-based solution to recover or unbrick Hikvision devices using TFTP. It includes two main components:

start.sh: A Bash script to configure the network interface and execute the Python server.
hikvision_tftpd3.py: A Python script implementing a minimal TFTP server to serve firmware files to Hikvision devices.
Files Overview
start.sh
Purpose:
Configures your system's network interface to the required IP address (192.0.0.128).
Checks if the IP address is already assigned to avoid conflicts.
Executes the TFTP server implemented in hikvision_tftpd3.py.
Cleans up the network configuration after the script completes or is interrupted.
Features:
Interface Detection:
Automatically detects the first active Ethernet interface.
IP Assignment:
Sets the interface's IP address to 192.0.0.128 (required for Hikvision recovery mode).
Ensures the IP is not already assigned before attempting to configure it.
Error Handling:
Handles various errors like missing permissions or unavailable network interfaces gracefully.
Cleanup:
Automatically removes the assigned IP address after the script completes, even if terminated early (e.g., via Ctrl+C).
Usage:
bash
Copy code
sudo ./start.sh
Example Output:
bash
Copy code
Found Ethernet interface: eth0
Setting IP address of eth0 to 192.0.0.128...
Starting Python script...
Script completed successfully!
Cleaning up: Removing IP address 192.0.0.128 from eth0...
Done!
hikvision_tftpd3.py
Purpose:
Implements a minimal TFTP server to serve firmware files to Hikvision devices.
Features:
TFTP Protocol:
Supports TFTP's Read Request (RRQ) operation to send firmware files in response to client requests.
Handshake Support:
Responds to Hikvision-specific "magic" handshake packets to initiate the recovery process.
Configurable Block Size:
Automatically adjusts the TFTP block size based on client options for optimal performance.
Error Handling:
Provides detailed logs for unexpected packets or errors during the TFTP process.
Usage:
The script is typically executed by start.sh. However, it can also be run independently if the required network configuration is already in place:

bash
Copy code
python3 ./hikvision_tftpd3.py --server-ip 192.0.0.128
Command-Line Arguments:
--filename (default: digicap.dav): The firmware file to serve via TFTP. Ensure the file is present in the same directory as the script.
--server-ip (default: 192.0.0.128): The IP address the TFTP server binds to. This must match the device's recovery expectations.
Example Output:
bash
Copy code
Setting block size to 512
Serving 102400-byte digicap.dav (block size 512, 200 blocks)
Replied to magic handshake request.
Starting transfer
  53:    5 /  200 [#####                     ]
  ...
  53:  200 /  200 [##########################]
  Done!
Workflow
Run the start.sh script:

Configures the network interface.
Launches the TFTP server (hikvision_tftpd3.py).
The Hikvision device in recovery mode:

Sends a handshake packet to the server.
Initiates a TFTP transfer to retrieve the firmware file (digicap.dav).
After successful recovery:

The TFTP transfer completes.
The network configuration is cleaned up by the start.sh script.
Prerequisites
Linux environment with Bash and Python 3 installed.
Administrative privileges (sudo) to configure the network interface.
The firmware file (digicap.dav) present in the same directory as the scripts.
Troubleshooting
Common Issues:
Permission Denied:
Run the script with sudo.
IP Address Already Assigned:
The script will handle this gracefully, but ensure no conflicting services are running.
Python Errors:
Ensure Python 3 is installed and available as python3.
Logs:
Both scripts provide detailed logs to help diagnose issues. Check the output for clues if something goes wrong.
Disclaimer
This tool is provided as-is under the MIT license. The authors are not responsible for any damage caused by improper use. Use at your own risk.
