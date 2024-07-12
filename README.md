# network-security-project

This project is a basic network scanning and port enumeration tool built using Python. It utilizes Scapy for network scanning and Nmap for port enumeration.

Features
Scan local network for connected devices.
Enumerate open ports on discovered devices.
Requirements
Python 3.x
Scapy
Nmap
Python Nmap
Setup
1. Clone the Repository
sh
Copy code
git clone https://github.com/nickwillson/network-security-project.git
cd network-security-tool
2. Make the Setup Script Executable
sh
Copy code
chmod +x setup.sh
3. Run the Setup Script
sh
Copy code
sudo ./setup.sh
This script will:

Update your package list.
Install python3-pip (Python package manager).
Install the Scapy library.
Install Nmap.
Install the Python Nmap library.
Usage
Run the Python Script
Once the setup is complete, you can run the Python script:

sh
Copy code
sudo python3 network_security_tool.py
Note: Running as sudo is required because network scanning typically needs elevated privileges.

Enter the IP Range for Scanning
When prompted, enter the IP range you want to scan, e.g., 192.168.1.1/24.

View the Output
The script will scan the specified IP range and display the IP, MAC addresses of discovered devices, and the state of their ports (open, closed, etc.).
