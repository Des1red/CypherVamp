#!/bin/bash

# Check if running with root privileges
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Installing third-party tools..."
echo ""

# Debugging: Print the list of installed packages before installation
echo "Before installation:"
apt list --installed

apt update
apt install -y golang-go nmap uniscan dirb hping3

# Check if installation was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to install one or more packages"
    exit 1
fi

echo "Creating necessary files..."

# Check if Scanners.go file exists in the current directory
if [ ! -f "$(pwd)/Scanners.go" ]; then
    echo "Error: Scanners.go file not found in $CYPHER_DIR"
    exit 1
fi

# Assuming Scanners.go is located in the current directory
go build Scanners.go

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Scanners"
    exit 1
fi

echo "Installation completed successfully"

echo "Type file to store command (leave empty for ~/.bashrc): "
read path

# Check if the path is empty, and set it to ~/.bashrc if so
if [ -z "$path" ]; then
    path=~/.bashrc
fi

# Use eval to expand the tilde in the path
eval path="$path"

# Check if the file exists before attempting to append the alias
if [ -f "$path" ]; then
    echo "alias cypher='$(pwd)/Scanners'" >> "$path"
    if grep -q "alias cypher='$(pwd)/Scanners'" "$path"; then
        echo "Alias 'cypher' was set successfully in $path."
    else
        echo "There was an error setting the alias 'cypher' in $path."
    fi
else
    echo "The file $path does not exist."
fi
