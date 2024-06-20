#!/bin/bash

echo "Updating package lists..."
sudo apt-get update

echo "Installing pip..."
sudo apt-get install -y python3-pip

echo "Installing Scapy..."
sudo pip3 install scapy

echo "Installing python-nmap..."
sudo pip3 install python-nmap

echo "Installation completed successfully!"
