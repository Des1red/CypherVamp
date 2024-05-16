#!/bin/bash

# Check if running with root privileges
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Installing third-party tools..."
echo ""

# Debugging: Print the list of installed packages before installation
echo "Before installation, already installed packages: "
apt list --installed
echo ""
echo "Installing essential tools ."
echo ""
apt install -y golang-go nmap uniscan dirb hping3 aircrack-ng 
echo ""

# Check if installation was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to install one or more packages"
    exit 1
fi

echo "Creating necessary files..."

# Check if Scanners.go file exists in the current directory
if [ ! -f "$(pwd)/Scanners.go" ]; then
    echo "Error: Scanners.go file not found in $(pwd)"
    exit 1
fi

# Assuming Scanners.go is located in the current directory
go build -o cypher Scanners.go

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Scanners"
    exit 1
fi

echo "Installation completed successfully"
echo ""
echo "You can now run sudo ./Scanners <<option>>"