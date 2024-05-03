#!/bin/bash

# Check if running with root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Installing third-party tools..."
echo ""
apt update
apt install -y golang-go nmap uniscan dirb hping3

# Check if installation was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to install one or more packages"
    exit 1
fi

echo "Creating necessary files..."
go build Scanners.go

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Scanners"
    exit 1
fi
echo ""
echo ""
echo "Installation completed successfully"
echo "To use the Cypher tool, please follow these steps:"
echo "1. Navigate to the directory containing the 'Scanners' executable."
echo "2. Add an alias to the 'Scanners' executable by running:"
echo "   For Bash: alias cypher=\"$(pwd)/Scanners\""
echo "   For Zsh:  alias cypher=\"$(pwd)/Scanners\""
echo "3. You can now use the 'cypher' command to start the scan."