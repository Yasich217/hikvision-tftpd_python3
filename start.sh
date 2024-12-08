#!/bin/bash

# Function to print an error message and exit
error_exit() {
    echo "Error: $1"
    exit 1
}

# Function to check if the IP is already assigned
is_ip_assigned() {
    ip addr show dev "$1" | grep -q "$2"
    return $?
}

# Cleanup function to remove the IP address
cleanup() {
    if is_ip_assigned "$INTERFACE" "$IP"; then
        echo "Cleaning up: Removing IP address $IP from $INTERFACE..."
        sudo ip addr del "$IP/24" dev "$INTERFACE" || echo "Warning: Failed to remove IP address. It may have already been removed."
    fi
}

# Trap cleanup to run on exit or script termination
trap cleanup EXIT

# Step 1: Get the Ethernet interface name
INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -m 1 '^[e]')
if [ -z "$INTERFACE" ]; then
    error_exit "Could not find an Ethernet interface. Please check your network connections."
fi
echo "Found Ethernet interface: $INTERFACE"

# Step 2: Check if the IP address is already assigned
IP="192.0.0.128"
if is_ip_assigned "$INTERFACE" "$IP"; then
    echo "IP address $IP is already assigned to $INTERFACE."
else
    echo "Setting IP address of $INTERFACE to $IP..."
    sudo ip addr add "$IP/24" dev "$INTERFACE" || error_exit "Failed to set IP address. Please run as root."
fi

# Step 3: Run the Python script
echo "Starting Python script..."
python3 ./hikvision_tftpd3.py --server-ip "$IP" || error_exit "Python script failed to run."

echo "Script completed successfully!"
