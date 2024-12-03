# Panorama Interface Collector

This script connects to multiple Panorama devices, retrieves information about managed firewalls and their interfaces, and outputs the data into CSV files. It securely prompts for credentials and handles connection fallbacks for robust execution.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)

## Features

- Connects to multiple Panorama devices listed in the `PANORAMAS` dictionary.
- Retrieves a list of managed firewalls from each Panorama.
- Connects to each firewall to collect interface data.
- Parses interface information and outputs it to CSV files.
- Securely prompts for username and password using the command line.

## Prerequisites

- **Python 3.6 or higher**
- **Required Python Libraries:**
  - `paramiko`
  - `netmiko`
  - `pan-os-python`
  - `getpass` (built-in module, no installation needed)

Install the required libraries using the following command:

```bash
pip install paramiko netmiko pan-os-python
```

## Installations

Clone the repository:

Replace yourusername and your-repo-name with your actual GitHub username and repository name.
```
git clone https://github.com/github.com/ncarabajal/palo-alto-interface-summary
cd palo-alto-interface-summary
```
Set up a virtual environment (optional but recommended):
```
python -m venv venv
source venv/bin/activate

# On Windows, use 'venv\Scripts\activate'
```
Install dependencies:

Option 1: Using requirements.txt

If you have a requirements.txt file in your repository, install the dependencies with:
```
pip install -r requirements.txt
```
Make sure your requirements.txt includes:
```
paramiko
netmiko
pan-os-python
```
Option 2: Install libraries individually
```
pip install paramiko netmiko pan-os-python
```
## Usage
Run the script:
```
python script.py
```
Enter your credentials when prompted:
```
Enter username: your_username
Enter password:
```
Note: The password input is hidden for security.

Wait for the script to complete.

The script will connect to each Panorama device, retrieve managed devices, and collect interface data.
It will output the data into CSV files named after each Panorama device, e.g., latam-interfaces.csv, latam-management-interfaces.csv.
Review the output files:

The CSV files will be located in the same directory as the script.

## Configuration
Panorama Devices:

To modify the list of Panorama devices, edit the PANORAMAS dictionary in the script:

python
Copy code
PANORAMAS = {
    "latam": "ar1vpanorama.turner.com",
    "ppano": "ppano.net.wbd.com",
    "epano": "epano.net.wbd.com",
    "dpano": "dpano.net.wbd.com",
    "wbpano": "wb-us-bur-corp-vpan1.warnermedia.com"
}
