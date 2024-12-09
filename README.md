# Hikvision NVR Unbrick Tool (Python 3 Upgrade)

This tool is specifically designed to help unbrick **DS-7608NI-i2/8p** Hikvision NVR devices. Other models have not been tested, and functionality is not guaranteed for those.

It upgrades the previous Python 2-based script to Python 3, as Python 2 is now deprecated. This ensures compatibility with modern systems.

> **Note:** The scripts **hikvision_tftpd.py** and **hikvision_tftpd_test.py** are legacy files and are provided for historical purposes. They are based on Python 2, and it is recommended to use the Python 3 script (**hikvision_tftpd3.py**) for future use.

---

## Prerequisites

- **Python 3**: This tool is written for Python 3, so make sure it is installed on your system.
- **TFTP Server**: The tool uses TFTP for file transfers. Ensure that your system has a working TFTP server, or use the provided script to start the server.
- **Linux **: The provided `start.sh` script is designed for Linux. Windows users should use alternative methods to execute the Python script.

---

## Installation

1. **Clone the Repository**  
   Clone this repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/sbeehre/hikvision-tftpd_python3.git
   cd hikvision-tftpd_python3
   ```

2. **Make the `start.sh` Script Executable**  
   On Linux, you will need to give execution permission to the `start.sh` script. Run the following command:

   ```bash
   sudo chmod +x start.sh
   ```

3. **Install Python 3 (if not already installed)**  
   Make sure Python 3 is installed on your machine. You can install it using your system's package manager.

---

## Usage

### Running the Tool on Linux

1. **Prepare Your Network Interface**  
   Make sure your network interface is configured and ready for the TFTP transfer. The script will set your server's IP to `192.0.0.128`, so ensure this address is not already in use on your network.

2. **Execute the Start Script**  
   Run the `start.sh` script to initiate the tool:

   ```bash
   ./start.sh
   ```

   The script will:
   - Assign the IP address `192.0.0.128` to your network interface.
   - Launch the Python 3 script (`hikvision_tftpd3.py`).
   - Start the TFTP transfer process.

3. **Monitor the Progress**  
   The terminal will display progress updates, showing the number of blocks transferred and the current block size.

---

## Troubleshooting

- **IP Conflict**: Ensure that the IP `192.0.0.128` is available. If it is already assigned to another device, the script may fail. You can manually configure your interface if needed.
- **Script Failure**: If the script fails to start, check if Python 3 is installed and ensure the necessary dependencies are met.
- **Compatibility**: This tool is specifically designed for **DS-7608NI-i2/8p** models. Other models may not work as expected.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

- This tool is based on previous work, but it has been updated to support Python 3 due to the deprecation of Python 2.

