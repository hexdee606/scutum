import argparse
import sys
import socket
import whois
import dns.resolver
import requests
from tqdm import tqdm
import time

repo_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"

info = [
    ['sr', 'title', 'information'],
    ['01', 'project name', 'Scutum'],
    ['02', 'version']
]


def perform_auto_port_scan(ip_address):
    try:
        # Check if the input is an IP address or URL
        if ip_address.replace(".", "").isnumeric():
            host = ip_address
        else:
            host = socket.gethostbyname(ip_address)

        open_ports = []

        # Perform a port scan from port 1 to 65535 with a progress bar
        with tqdm(total=65535) as pbar:
            for port in range(1, 65536):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Set a timeout for the connection attempt

                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

                pbar.update(1)  # Update the progress bar

        # Format the output
        if len(open_ports) > 0:
            output = f"Open ports found for {ip_address}:\n"
            for port in open_ports:
                output += f"  - Port {port}\n"
        else:
            output = f"No open ports found for {ip_address}.\n"

        return output

    except socket.gaierror:
        return f"Error: Failed to resolve IP address or hostname for {ip_address}."

    except socket.timeout:
        return f"Error: Connection timed out for {ip_address}."

    except socket.error as e:
        return f"Error: Socket error occurred for {ip_address}. Reason: {str(e)}"

    except Exception as e:
        return f"Error: An unexpected error occurred. Reason: {str(e)}"

    except KeyboardInterrupt:
        return f"Port scan interrupted by user for {ip_address}."


def perform_range_port_scan(ip_address, start, end):
    try:
        # Check if the input is an IP address or URL
        if ip_address.replace(".", "").isnumeric():
            host = ip_address
        else:
            host = socket.gethostbyname(ip_address)

        # Validate the start and end port numbers
        if end > 65535:
            raise ValueError("The end port number exceeds the maximum port number (65535).")

        if start > end:
            raise ValueError("The start port number should be less than or equal to the end port number.")

        open_ports = []

        # Perform a port scan within the specified range with a progress bar
        with tqdm(total=end - start + 1) as pbar:
            for port in range(start, end + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Set a timeout for the connection attempt

                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

                pbar.update(1)  # Update the progress bar

        # Format the output
        output = f"Found open ports for {ip_address}:\n"
        if len(open_ports) > 0:
            for port in open_ports:
                output += f"  - Port {port}\n"
        else:
            output += "No open ports found within the specified range.\n"

        return output

    except socket.gaierror:
        return f"Error: Failed to resolve IP address or hostname for {ip_address}."

    except socket.timeout:
        return f"Error: Connection timed out for {ip_address}."

    except socket.error as e:
        return f"Error: Socket error occurred for {ip_address}. Reason: {str(e)}"

    except ValueError as e:
        return f"Error: {str(e)}"

    except Exception as e:
        return f"Error: An unexpected error occurred. Reason: {str(e)}"

    except KeyboardInterrupt:
        return f"Port scan interrupted by user for {ip_address}."


def perform_mapping_scan(url):
    try:
        # Resolve the IP address associated with the URL
        with tqdm(total=2, desc="Performing mapping scan", unit="scan") as pbar:
            ip_address = socket.gethostbyname(url)
            pbar.update(1)
            domain_info = whois.whois(url)
            pbar.update(1)

        # Extract the relevant information from the WHOIS result
        domain_name = domain_info.domain_name
        dns_servers = domain_info.name_servers
        server_location = domain_info.country

        # Format the output
        output = f"Domain name associated with {url}: {domain_name}\n"
        output += f"IP address for {url}: {ip_address}\n"
        output += f"DNS servers associated with {url}: {dns_servers}\n"
        output += f"Server location for {url}: {server_location}\n"

        return output

    except socket.gaierror:
        return f"Error: Failed to resolve IP address or hostname for {url}."

    except Exception as e:
        return f"Error: An unexpected error occurred. Reason: {str(e)}"

    except KeyboardInterrupt:
        return f"mapping scan interrupted by user for {ip_address}."


def perform_domain_scan(url, dns_server):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]

        answers = resolver.resolve(url)
        ip_address = answers[0].to_text()
        result = f"IP address for {url} for {dns_server} is {ip_address}"
    except dns.resolver.NXDOMAIN:
        result = f"Error: Domain {url} not found"
    except dns.resolver.Timeout:
        result = f"Error: Timeout while querying {url}"
    except dns.resolver.NoAnswer:
        result = f"Error: No answer for {url}"
    except dns.exception.DNSException as e:
        result = f"Error: {str(e)}"

    except KeyboardInterrupt:
        return f"domain scan interrupted by user for {url}."

    return result


def download_subdomain_list():
    file_name = "subdomain.txt"
    response = requests.get(repo_url)
    with open(file_name, 'wb') as file:
        file.write(response.content)


def check_subdomain_availability(url, subdomain):
    try:
        target = f"{subdomain}.{url}"
        answers = dns.resolver.resolve(target, 'A')
        if answers:
            return subdomain
    except dns.resolver.NXDOMAIN:
        pass
    except KeyboardInterrupt:
        return f"subdomain scan interrupted by user for {url}."
    except Exception as e:
        pass


def perform_auto_subdomain_scan(url):
    try:
        download_subdomain_list()
        subdomain_file = "subdomain.txt"
        subdomains = []
        with open(subdomain_file, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]

        available_subdomains = []
        with tqdm(total=len(subdomains), ncols=80, desc="Scanning") as pbar:
            for subdomain in subdomains:
                result = check_subdomain_availability(url, subdomain)
                time.sleep(0.5)
                if result:
                    available_subdomains.append(result)
                pbar.update(1)

        with tqdm(total=len(available_subdomains), ncols=80, desc="generating output") as pbar:
            output = f'found subdomains for {url} are:\n'
            for subdomain_from_list in available_subdomains:
                pbar.update(1)
                output = output + f'{subdomain_from_list}.{url}\n'
            return str(output)
    except KeyboardInterrupt:
        return f"subdomain scan interrupted by user for {url}."


def perform_custom_subdomain_scan(url, subdomain_list):
    try:
        subdomains = []
        with open(subdomain_list, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]

        available_subdomains = []
        with tqdm(total=len(subdomains), ncols=80, desc="Scanning") as pbar:
            for subdomain in subdomains:
                result = check_subdomain_availability(url, subdomain)
                if result:
                    available_subdomains.append(result)
                pbar.update(1)

        with tqdm(total=len(available_subdomains), ncols=80, desc="generating output") as pbar:
            output = f'found subdomains for {url} are:\n'
            for subdomain_from_list in available_subdomains:
                pbar.update(1)
                output = output + f'{subdomain_from_list}.{url}\n'
            return str(output)
    except KeyboardInterrupt:
        return f"subdomain scan interrupted by user for {url}."


def store_output_in_file(output):
    # Store the output in result1.txt file
    with open('result.txt', 'w') as file:
        file.write(output)


def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description="Scutum - Website/Server Vulnerability Detection Tool")

    # Add the scan argument
    parser.add_argument('--scan', choices=['port', 'mapping', 'domain', 'subdomain'],
                        help='Specify the type of scan')

    # Add the optional arguments
    parser.add_argument('--url', '-u', help='Specify the target URL to scan')
    parser.add_argument('--ip-address', '-ip', help='Specify the target IP address to scan')
    parser.add_argument('--start', '-s', type=int, help='Specify the starting point or range for port scanning')
    parser.add_argument('--end', '-e', type=int, help='Specify the ending point or range for port scanning')
    parser.add_argument('--auto', '-a', action='store_true', help='Enable automatic scanning mode')
    parser.add_argument('--dns', help='Specify the DNS server IP address for domain scanning')
    parser.add_argument('--list', help='Specify the file containing subdomains for scanning')
    parser.add_argument('--version', '-v', action='store_true', help='Display information about me')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Perform actions based on the scan argument
    if args.scan == 'port':
        if args.ip_address:
            if args.auto:
                output = perform_auto_port_scan(args.ip_address)
            elif args.start is not None and args.end is not None:
                output = perform_range_port_scan(args.ip_address, args.start, args.end)
            else:
                sys.exit(
                    'Error: Please provide either the --auto flag or both --start and --end arguments for port scan.')
            store_output_in_file(output)
        else:
            sys.exit('Error: Please provide a target IP address using the --ip-address/-ip argument for port scan.')

    elif args.scan == 'mapping':
        if args.url:
            output = perform_mapping_scan(args.url)
            store_output_in_file(output)
        else:
            sys.exit('Error: Please provide a target URL using the --url/-u argument for mapping scan.')

    elif args.scan == 'domain':
        if args.url and args.dns:
            output = perform_domain_scan(args.url, args.dns)
            store_output_in_file(output)
        else:
            sys.exit('Error: Please do not provide the --url/-u or --dns arguments for domain scan.')

    elif args.scan == 'subdomain':
        if args.url:
            if args.auto:
                output = perform_auto_subdomain_scan(args.url)
            elif args.list:
                output = perform_custom_subdomain_scan(args.url, args.list)
            else:
                sys.exit('Error: Please provide either the --auto or --list argument for subdomain scan.')
            store_output_in_file(output)
        else:
            sys.exit('Error: Please provide a target URL using the --url/-u argument for subdomain scan.')
    elif args.version:
        print('version')
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
