#!/bin/bash

# Define the absolute path to the Scanners directory
SCANNERS_DIR="$(pwd)"

# Check if running with root privileges
if [ "$(id -u)" -ne 0 ]; then
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

# Variable to track if alias was successfully added to any shell
alias_added=false

# Save the alias definition to the Bash configuration file
if ! echo "alias cypher='.$SCANNERS_DIR/Scanners'" >> ~/.bashrc; then
    echo "Error: Failed to append alias definition to ~/.bashrc"
else
    alias_added=true
fi

# Check if Zsh is installed and it's the current shell
if [ -n "$(command -v zsh)" ] && [ "$SHELL" = "$(command -v zsh)" ]; then
    # Save the alias definition to the Zsh configuration file
    if ! echo "alias cypher='.$SCANNERS_DIR/Scanners'" >> ~/.zshrc; then
        echo "Error: Failed to append alias definition to ~/.zshrc"
    else
        alias_added=true
    fi
fi

# Apply the changes to the current shell session
source ~/.bashrc
if [ -n "$(command -v zsh)" ] && [ "$SHELL" = "$(command -v zsh)" ]; then
    source ~/.zshrc
fi

# Display message if alias was added to at least one shell
if [ "$alias_added" = true ]; then
    echo "Alias 'cypher' has been set to '.$SCANNERS_DIR/Scanners'."
    echo "You can now use the 'cypher' command to start the scan."
fi