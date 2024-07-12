import nmap
import subprocess

def scan_open_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')  # Scanning ports 1 to 1024
    for host in nm.all_hosts():
        print(f'Scanning {host}...')
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                print(f'Port : {port}\tState : {nm[host][proto][port]["state"]}')

def check_outdated_software(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')
    for host in nm.all_hosts():
        print(f'Software versions for {host}...')
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                print(f'Port : {port}\tProduct : {product}\tVersion : {version}')

def check_basic_misconfigurations():
    result = subprocess.run(['nmap', '--script', 'vuln'], capture_output=True, text=True)
    print(result.stdout)

def main():
    target = input('Enter the target (IP or hostname): ')
    print('Scanning for open ports...')
    scan_open_ports(target)
    print('\nChecking for outdated software...')
    check_outdated_software(target)
    print('\nChecking for basic misconfigurations...')
    check_basic_misconfigurations()

if __name__ == "__main__":
    main()
