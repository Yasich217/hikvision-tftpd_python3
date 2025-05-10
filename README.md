# TFTP Handshake Responder for Hikvision Devices

This script acts as a TFTP Handshake Responder for Hikvision devices, allowing file transfers via TFTP based on a specific handshake protocol.

## Overview

The script listens for a handshake request from Hikvision devices and responds by transferring files using TFTP. It is designed to work on both Linux and Windows environments.

## Prerequisites

- Python 3.x
- Administrative privileges for creating raw sockets (necessary for Windows).

## Installation

1. Clone the repository or download the script.
2. Ensure you have Python 3.x installed.

## Usage

Run the script with the following command:

```bash
python tftp_responder.py --server-ip <your-server-ip>
