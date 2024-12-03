import csv
import re
from paramiko import SSHClient, AutoAddPolicy, RSAKey, SSHException
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
from panos import panorama
from panos.firewall import Firewall
from panos.device import SystemSettings
from panos.errors import PanDeviceError
import getpass  # Import getpass for secure password input

# Define multiple Panorama devices
PANORAMAS = {
    "pano1": "pano1-address",
    "pano2": "pano2-address",
    "pano3": "pano3-address",

}

def get_managed_devices(pan):
    try:
        # Refresh devices
        print("Attempting to refresh devices...")
        devices = pan.refresh_devices(expand_vsys=False, include_device_groups=False)
        print(f"Devices found: {len(devices)}")
        for device in devices:
            system_settings = device.findall(SystemSettings)
            if system_settings:
                ip_address = system_settings[0].ip_address
                hostname = system_settings[0].hostname
                print(f"Device: {device.serial}, IP: {ip_address}, Hostname: {hostname}")
                device.ip_address = ip_address  # Store IP address in the device object
                device.hostname = hostname      # Store hostname in the device object
            else:
                print(f"No system settings found for device: {device.serial}")
        return devices
    except PanDeviceError as e:
        print(f"Failed to refresh devices: {e}")
        return []

def connect_with_fallback(device_ip, username, password):
    """Attempt to connect to a device, falling back to specific options if initial connection fails."""
    device = {
        'device_type': 'paloalto_panos',
        'host': device_ip,
        'username': username,
        'password': password,
        'global_cmd_verify': False,
        'auth_timeout': 30,
        'banner_timeout': 30,
        'conn_timeout': 30,
        'session_timeout': 60,
        'use_keys': False,
        'allow_agent': False,
        'ssh_config_file': None,
    }
    try:
        # First connection attempt
        net_connect = ConnectHandler(**device)
        return net_connect
    except (NetMikoTimeoutException, NetMikoAuthenticationException, SSHException) as e:
        # If initial connection fails, try with specific SSH options
        print(f"Initial connection to {device_ip} failed, retrying with specific SSH options...")
        try:
            device['disabled_algorithms'] = {'keys': ['rsa-sha2-256', 'rsa-sha2-512']}
            net_connect = ConnectHandler(**device)
            return net_connect
        except (NetMikoTimeoutException, NetMikoAuthenticationException, SSHException) as e:
            print(f"Failed to connect to {device_ip} with specific SSH options: {e}")
            return None

def run_command_on_device(device_ip, username, password, command):
    try:
        net_connect = connect_with_fallback(device_ip, username, password)
        if net_connect:
            output = net_connect.send_command(command, expect_string=r'[>#]', delay_factor=2, max_loops=1000)
            net_connect.disconnect()
            return output
        else:
            return ""
    except Exception as e:
        print(f"An error occurred: {e}")
        return ""

def parse_interfaces(output):
    interfaces = []
    current_interface = None
    parsing_logical_interfaces = False
    for line in output.splitlines():
        line = line.rstrip('\n')
        if 'total configured logical interfaces' in line.lower():
            parsing_logical_interfaces = True
            continue 
        if parsing_logical_interfaces:
            if not line.strip() or set(line.strip()) == set('-'):
                continue
            if 'name' in line.lower() and 'address' in line.lower():
                continue
            if re.match(r'^\s', line):
                address = line.strip()
                if address and address != 'N/A' and current_interface:
                    current_interface['addresses'].append(address)
            else:
                parts = re.split(r'\s+', line)
                if len(parts) < 7:
                    continue
                interface_name = parts[0]
                id = parts[1]
                vsys = parts[2]
                zone = parts[3]
                forwarding = parts[4]
                tag = parts[5]
                address = parts[6]
                # Ensure id and vsys are digits to confirm this is an interface entry
                if not id.isdigit() or not vsys.isdigit():
                    continue
                current_interface = {'name': interface_name, 'zone': zone, 'addresses': []}
                if address and address != 'N/A':
                    current_interface['addresses'].append(address)
                interfaces.append(current_interface)
    return interfaces

def process_interface_name(interface_name, hostname):
    substitutions = {
        'ethernet': f'{hostname}-e',
        'loopback': f'{hostname}-lo',
        'tunnel': f'{hostname}-tu',
        'ha': f'{hostname}-ha',
        'ae': f'{hostname}-ae',
        'management': f'{hostname}-mgmt',
    }
    for key in sorted(substitutions.keys(), key=len, reverse=True):
        interface_name = interface_name.replace(key, substitutions[key])
    return interface_name

def get_management_ip(device_ip, username, password):
    command = 'show interface management | match "Ip address:"'
    output = run_command_on_device(device_ip, username, password, command)
    if output:
        match = re.search(r'Ip address:\s+(\S+)', output)
        if match:
            management_ip = match.group(1)
            return management_ip
    return None

def process_panorama(pano_name, pano_ip, username, password):
    print(f"Connecting to Panorama '{pano_name}' at IP '{pano_ip}'")
    # Connect to Panorama
    pan = panorama.Panorama(pano_ip, username, password)
    devices = get_managed_devices(pan)
    all_interfaces = []
    management_interfaces = []
    failed_devices = []

    for device in devices:
        if not isinstance(device, Firewall):
            continue  # Skip non-firewall devices

        hostname = device.hostname
        device_ip = device.ip_address
        if not device_ip:
            print(f"No IP address found for device {hostname}, skipping...")
            continue

        print(f"Connecting to device {hostname} at {device_ip}")

        command = 'show interface all | except N/A'
        response = run_command_on_device(device_ip, username, password, command)
        if not response:
            print(f"No response from {hostname} at {device_ip}, skipping...")
            failed_devices.append((hostname, device_ip))
            continue

        print(f"Response from {hostname}:\n{response}")

        interfaces = parse_interfaces(response)
        print(f"Parsed interfaces for {hostname}: {interfaces}")

        for interface in interfaces:
            original_interface_name = interface['name']
            name = process_interface_name(original_interface_name, hostname)
            zone = interface['zone']
            addresses = interface['addresses']
            for address in addresses:
                all_interfaces.append([name, address, zone])

        management_ip = get_management_ip(device_ip, username, password)
        if management_ip:
            interface_name = process_interface_name('management', hostname)
            management_interfaces.append([interface_name, management_ip])
        else:
            print(f"Could not retrieve management IP for {hostname}")

    # Write the collected interfaces to a CSV file for this Panorama
    csv_file = f"{pano_name}-interfaces.csv"
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['name', 'address', 'zone'])
        for interface in all_interfaces:
            writer.writerow(interface)

    print(f"Interface data for Panorama '{pano_name}' has been written to {csv_file}")

    # Write the management interfaces to a separate CSV file
    management_csv_file = f"{pano_name}-management-interfaces.csv"
    with open(management_csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['interface', 'IP'])
        for interface in management_interfaces:
            writer.writerow(interface)

    print(f"Management interface data for Panorama '{pano_name}' has been written to {management_csv_file}")

    if failed_devices:
        print(f"\nDevices that failed to connect for Panorama '{pano_name}':")
        for hostname, device_ip in failed_devices:
            print(f"Hostname: {hostname}, IP: {device_ip}")

def main():
    # Prompt the user for username and password
    USERNAME = input("Enter username: ")
    PASSWORD = getpass.getpass("Enter password: ")

    for pano_name, pano_ip in PANORAMAS.items():
        process_panorama(pano_name, pano_ip, USERNAME, PASSWORD)

if __name__ == "__main__":
    main()
