<h1 align="center">VNC&RDP Scanner</h1>

## About The Project
<br />

VNC&RDP Scanner is a simple tool designed to perform basic scans of RDP and VNC service availability and check VNC configuration. The script uses a list of IP addresses saved in the ip_list.csv file and after performing the scan generates a report in the file wyniki_skanowania.txt.

## Getting Started
Below I'll give you information on how to properly run the tool.

### Prerequisites
Before running the script, make sure you have all the necessary modules installed. Please note that if you want to use integration with VirusTotal and Shodan, you must add your API key to the script.
# Note! Remember that before you perform a scan, the owner of the target IP address must consent to its scanning!

To run the script, follow the steps below:

Cloning a repository
  ```sh
  git clone https://github.com/mikolajdreger/VNC-RDP-Scanner.git
  ```
Adding execution permissions
  ```sh
  chmod +x vnc_rdp_scanner.py
  ```
Running the script
  ```sh
  python3 ./vnc_rdp_scanner.py
  ```
