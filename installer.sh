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
# Assuming Scanners.go is located in the same directory as this script
go build Scanners.go

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Scanners"
    exit 1
fi
echo ""
echo ""
echo "Installation completed successfully"

# Define the alias command
alias cypher="/home/kali/Scanners"

# Save the changes to the Bash configuration file of the current user
echo 'alias cypher="$(pwd)/Scanners"' >> ~/.bashrc

# Check if Zsh is installed
if [ -n "$(command -v zsh)" ]; then
    # Save the changes to the Zsh configuration file of the current user
   echo 'alias cypher="$(pwd)/Scanners"' >> ~/.zshrc
fi

# Apply the changes to the current shell session
source ~/.bashrc
source ~/.zshrc  

echo "Alias 'cypher' has been set to '\"$(pwd)/Scanners\'."
echo "3. You can now use the 'cypher' command to start the scan."
