#!/usr/bin/python3
# -*- coding: UTF-8 -*-

"""
Scutum - Website/Server Vulnerability Detection CLI Tool

Description: Scutum is a powerful CLI tool designed to detect vulnerabilities in websites and servers. It offers a
range of features, including: - Port Scanning: Identify open ports on websites and server links. - Mapping: Retrieve
information about domain names, IP addresses, associated DNS servers, and server locations. - Domain Analysis: Find
the IP address of a website on a user-defined DNS server. - Subdomain Discovery: Quickly scan and discover subdomains
associated with a website (scans 200 subdomains within 5 seconds).

I would like to highlight that Scutum is an open-source project licensed under CC0.1, granting you the freedom to
use, modify, and distribute it without any constraints.

Author:
Dipen Chavan

Version:
0.3

License:
CC0 (Creative Commons Zero)

"""

__author__ = "DIPEN CHAVAN @HEXDEE606"
__version__ = "0.3"
__license__ = "CC0"
__build__ = "beta"

import sys
import time
import whois
import socket
import colorama
import textwrap
import argparse
import requests
import dns.resolver
from tqdm import tqdm
from os import name, system

repo_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million" \
           "-110000.txt"

try:
    colorama.init()
    """
    :return: forehead font colors and symbols  for command line interface
    """
    W = colorama.Fore.RESET  # white
    G = colorama.Fore.GREEN  # green
    Y = colorama.Fore.YELLOW  # yellow
    B = colorama.Fore.BLUE  # blue
    R = colorama.Fore.RED  # red
    none_symbol = ' '  # bullet W
    info_symbol = 'i'  # information source B
    error_symbol = 'x'  # cross mark R
    warning_symbol = '!'  # warning sign Y
    success_symbol = '√'  # check mark G
except Exception as no_colour_error:
    G = Y = B = R = W = ''  # no colors


def clear():
    """
    :return: The clear function is used to clear the command line interface of windows or Linux based systems.
    """
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def display():
    clear()
    print("%s██████████████████████████████████████████████████████████████████████" % W)
    print("%s███████  ███████  ██████ ██    ██ ████████ ██    ██ ███    ███  ██████" % Y)
    print("%s███████  ██      ██      ██    ██    ██    ██    ██ ████  ████  ██████" % Y)
    print("%s███████  ███████ ██      ██    ██    ██    ██    ██ ██ ████ ██  ██████" % W)
    print("%s███████       ██ ██      ██    ██    ██    ██    ██ ██  ██  ██  ██████" % W)
    print("%s███████  ███████  ██████  ██████     ██     ██████  ██      ██  ██████" % G)
    print("%s█████████████ VERSION: {} █ BY: {} █████████████".format(__version__, __author__) % G)
    print("%s██████████████████████████████████████████████████████████████████████" % W)


def log(string, color, symbol):
    """
    To print output in console with forehead color and symbol.
    :param string: any message user want to display on console
    :param color: forehead font colors and symbols  for command line interface
    :param symbol: forehead font colors and symbols  for command line interface
    :return: well organised console output
    """

    wrapped_lines = textwrap.wrap(str(string), width=64)
    for wrapped_line in wrapped_lines:
        print("%s█ {:<1} {:<64} █".format(symbol, wrapped_line) % color)


def perform_auto_port_scan(ip_address):
    try:
        display()
        # Check if the input is an IP address or URL
        if ip_address.replace(".", "").isnumeric():
            host = ip_address
        else:
            host = socket.gethostbyname(ip_address)
        open_ports = []
        # Perform a port scan from port 1 to 65535 with a progress bar
        with tqdm(total=65535, ncols=70, desc="Performing port scan", unit="scan") as pbar:
            for port in range(1, 65535):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Set a timeout for the connection attempt
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                pbar.update(1)  # Update the progress bar
        # Format the output
        output = "█ SR   █ OPEN PORTS FOR {:<45}█\n".format(ip_address)
        if len(open_ports) > 0:
            for i in range(0, len(open_ports)):
                output += "█ {:<4} █ {:<59} █\n".format(i + 1, open_ports[i])
            output += "█ The user's range yielded results within the specified parameters.  █\n"
        else:
            output = "█ {:<66} █\n".format("No open ports found for" + ip_address)
        return [output, False]
    except socket.gaierror:
        return [f"Error: Failed to resolve IP address or hostname for {ip_address}.", True]
    except socket.timeout:
        return [f"Error: Connection timed out for {ip_address}.", True]
    except socket.error as e:
        return [f"Error: Socket error occurred for {ip_address}. Reason: {str(e)}", True]
    except Exception as e:
        return [f"Error: An unexpected error occurred. Reason: {str(e)}", True]
    except KeyboardInterrupt:
        return [f"Port scan interrupted by user for {ip_address}.", True]


def perform_range_port_scan(ip_address, start, end):
    try:
        display()
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
        with tqdm(total=end - start + 1, ncols=70, desc="Performing port scan", unit="scan") as pbar:
            for port in range(start, end + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Set a timeout for the connection attempt
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                pbar.update(1)  # Update the progress bar
        # Format the output
        output = "█ SR   █ OPEN PORTS FOR {:<45}█\n".format(ip_address)
        if len(open_ports) > 0:
            for i in range(0, len(open_ports)):
                output += "█ {:<4} █ {:<59} █\n".format(i + 1, open_ports[i])
            output += "█ The user's range yielded results within the specified parameters.  █\n"
        else:
            output = "█ {:<66} █\n".format("No open ports found within the specified range.")
        return [output, False]
    except socket.gaierror:
        return [f"Error: Failed to resolve IP address or hostname for {ip_address}.", True]
    except socket.timeout:
        return [f"Error: Connection timed out for {ip_address}.", True]
    except socket.error as e:
        return [f"Error: Socket error occurred for {ip_address}. Reason: {str(e)}", True]
    except ValueError as e:
        return [f"Error: {str(e)}", True]
    except Exception as e:
        return [f"Error: An unexpected error occurred. Reason: {str(e)}", True]
    except KeyboardInterrupt:
        return [f"Port scan interrupted by user for {ip_address}.", True]


def perform_mapping_scan(url):
    try:
        display()
        # Resolve the IP address associated with the URL
        with tqdm(total=2, ncols=70, desc="Performing mapping scan", unit="scan") as pbar:
            ip_address = socket.gethostbyname(url)
            pbar.update(1)
            domain_info = whois.whois(url)
            pbar.update(1)
        # Extract the relevant information from the WHOIS result
        domain_name = domain_info.domain_name
        dns_servers = domain_info.name_servers
        server_location = domain_info.country
        # Format the output
        # Format the output for domain name
        if len(domain_name) > 0:
            output = "█ SR   █ DOMAIN NAME ASSOCIATED WITH {:<31} █\n".format(url)
            if isinstance(domain_name, list):
                for i in range(0, len(domain_name)):
                    output += "█ {:<4} █ {:<59} █\n".format(i + 1, domain_name[i])
            else:
                output += "█ {:<4} █ {:<59} █\n".format(1, domain_name)
        else:
            output = "█ {:<66} █\n".format("NO DOMAIN NAME ASSOCIATED WITH " + url)

        # Format the output for ip address
        output += "██████████████████████████████████████████████████████████████████████\n"
        if len(ip_address) > 0:
            output += "█ SR   █ IP ADDRESS ASSOCIATED WITH {:<32} █\n".format(url)
            if isinstance(ip_address, str):
                output += "█ {:<4} █ {:<59} █\n".format(1, ip_address)
            elif isinstance(ip_address, list):
                for i in range(0, len(ip_address)):
                    output += "█ {:<4} █ {:<59} █\n".format(i + 1, ip_address[i])
            else:
                output += "█ {:<4} █ {:<59} █\n".format(1, ip_address)
        else:
            output += "█ {:<66} █\n".format("NO IP ADDRESS ASSOCIATED WITH " + url)

        # Format the output for dns server
        output += "██████████████████████████████████████████████████████████████████████\n"
        if len(dns_servers) > 0:
            output += "█ SR   █ DNS SERVERS ASSOCIATED WITH {:<31} █\n".format(url)
            if isinstance(dns_servers, list):
                for i in range(0, len(dns_servers)):
                    output += "█ {:<4} █ {:<59} █\n".format(i + 1, dns_servers[i])
            elif isinstance(dns_servers, str):
                output += "█ {:<4} █ {:<59} █\n".format(1, dns_servers)
            else:
                output += "█ {:<66} █\n".format("INVALID DNS SERVER FORMAT: " + str(dns_servers))
        else:
            output += "█ {:<66} █\n".format("NO DNS SERVER ASSOCIATED WITH " + url)

        # Format the output for server location
        output += "██████████████████████████████████████████████████████████████████████\n"
        if len(server_location) > 0:
            output += "█ SR   █ SERVER LOCATION ASSOCIATED WITH {:<27} █\n".format(url)
            if isinstance(server_location, list):
                for i in range(0, len(server_location)):
                    output += "█ {:<4} █ {:<59} █\n".format(i + 1, server_location[i])
            elif isinstance(dns_servers, str):
                output += "█ {:<4} █ {:<59} █\n".format(1, server_location)
            else:
                output += "█ {:<4} █ {:<59} █\n".format(1, server_location)
        else:
            output += "█ {:<66} █\n".format("NO SERVER LOCATION ASSOCIATED WITH " + url)

        return [output, False]
    except socket.gaierror:
        return [f"Error: Failed to resolve IP address or hostname for {url}.", True]
    except Exception as e:
        return [f"Error: An unexpected error occurred. Reason: {str(e)}", True]
    except KeyboardInterrupt:
        return [f"mapping scan interrupted by user for {ip_address}.", True]


def perform_domain_scan(url, dns_server):
    try:
        display()
        with tqdm(total=4, ncols=70, desc="Performing domain scan", unit="Process") as pbar:
            resolver = dns.resolver.Resolver()
            pbar.update(1)
            resolver.nameservers = [dns_server]
            pbar.update(1)
            answers = resolver.resolve(url)
            pbar.update(1)
            ip_address = answers[0].to_text()
            result = "█ The IP address for {:<47} █\n".format(url)
            result += "█ On DNS server {:<52} █\n".format(dns_server)
            result += "█ is {:<63} █\n".format(ip_address)
            pbar.update(1)
            return [result, False]
    except dns.resolver.NXDOMAIN:
        return [f"Error: Domain {url} not found", True]
    except dns.resolver.Timeout:
        return [f"Error: Timeout while querying {url}", True]
    except dns.resolver.NoAnswer:
        return [f"Error: No answer for {url}", True]
    except dns.exception.DNSException as e:
        return [f"Error: {str(e)}", True]
    except KeyboardInterrupt:
        return [f"domain scan interrupted by user for {url}.", True]


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
        return [f"subdomain scan interrupted by user for {url}.", True]
    except Exception as e:
        pass


def perform_auto_subdomain_scan(url):
    try:
        display()
        download_subdomain_list()
        subdomain_file = "subdomain.txt"
        subdomains = []
        with open(subdomain_file, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]
        available_subdomains = []
        with tqdm(total=len(subdomains), ncols=70, desc="Performing subdomain scan", unit="Scan") as pbar:
            for subdomain in subdomains:
                result = check_subdomain_availability(url, subdomain)
                time.sleep(0.5)
                if result:
                    available_subdomains.append(result)
                pbar.update(1)
        with tqdm(total=len(available_subdomains), ncols=70, desc="Generating output", unit="Line") as pbar:
            if len(available_subdomains) > 0:
                output = "█ Subdomains were discovered for {:<35} █\n".format(url)
                output += "█ Total discovered subdomains are {:<34} █\n".format(len(available_subdomains))
                output += "█ SR   █ {:<59} █\n".format("SUBDOMAINS FOR " + url)
                for i in range(0, len(available_subdomains)):
                    output += "█ {:<4} █ {:<59} █\n".format(i + 1, available_subdomains[i] + "." + url)
            else:
                output = "█ No Subdomains were discovered for {:<32} █\n".format(url)
            return [output, False]
    except KeyboardInterrupt:
        return [f"subdomain scan interrupted by user for {url}.", True]


def perform_custom_subdomain_scan(url, subdomain_list):
    try:
        display()
        subdomains = []
        with open(subdomain_list, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]
        available_subdomains = []
        with tqdm(total=len(subdomains), ncols=70, desc="Performing subdomain scan", unit="Scan") as pbar:
            for subdomain in subdomains:
                result = check_subdomain_availability(url, subdomain)
                if result:
                    available_subdomains.append(result)
                pbar.update(1)
        with tqdm(total=len(available_subdomains), ncols=70, desc="Generating output", unit="Line") as pbar:
            if len(available_subdomains) > 0:
                output = "█ Subdomains were discovered for {:<35} █\n".format(url)
                output += "█ Total discovered subdomains are {:<34} █\n".format(len(available_subdomains))
                output += "█ SR   █ {:<59} █\n".format("SUBDOMAINS FOR " + url)
                for i in range(0, len(available_subdomains)):
                    output += "█ {:<4} █ {:<59} █\n".format(i + 1, available_subdomains[i] + "." + url)
            else:
                output = "█ No Subdomains were discovered for {:<32} █\n".format(url)
            return [output, False]
    except KeyboardInterrupt:
        return [f"subdomain scan interrupted by user for {url}.", True]


def store_output_in_file(output):
    # Store the output in result1.txt file
    if output[1]:
        display()
        log(output[0], R, error_symbol)
    else:
        with tqdm(total=1, ncols=70, desc="Writing output", unit="Line") as pbar:
            with open('result.txt', 'w', encoding='utf-8') as file:
                display()
                formatted_output = f"██████████████████████████████████████████████████████████████████████\n"
                formatted_output += f"███████  ███████  ██████ ██    ██ ████████ ██    ██ ███    ███  ██████\n"
                formatted_output += f"███████  ██      ██      ██    ██    ██    ██    ██ ████  ████  ██████\n"
                formatted_output += f"███████  ███████ ██      ██    ██    ██    ██    ██ ██ ████ ██  ██████\n"
                formatted_output += f"███████       ██ ██      ██    ██    ██    ██    ██ ██  ██  ██  ██████\n"
                formatted_output += f"███████  ███████  ██████  ██████     ██     ██████  ██      ██  ██████\n"
                formatted_output += f"█████████████ VERSION: {__version__} █ BY: {__author__} █████████████\n"
                formatted_output += f"██████████████████████████████████████████████████████████████████████\n"

                formatted_output += output[0]
                formatted_output += f"██████████████████████████████████████████████████████████████████████\n"
                file.write(formatted_output.encode('utf-8').decode('utf-8'))
                pbar.update(1)
    log("████████████████████████████████████████████████████████████████", W, none_symbol)


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
        if args.url:
            if not ("https://" in args.url or "http://" in args.url):
                if args.auto:
                    output = perform_auto_port_scan(args.url)
                elif args.start is not None and args.end is not None:
                    output = perform_range_port_scan(args.ip_address, args.start, args.end)
                else:
                    sys.exit(
                        'Error: Please provide either the --auto flag or both --start and --end arguments for port '
                        'scan.')
            else:
                sys.exit("Error: URLs starting with 'https://' or 'http://' are not allowed.")
            store_output_in_file(output)
        else:
            sys.exit('Error: Please provide either a target IP address using the --ip-address/-ip argument or a '
                     'target URL using the --url/-u argument for port scan.')
    elif args.scan == 'mapping':
        if args.url:
            if not ("https://" in args.url or "http://" in args.url):
                output = perform_mapping_scan(args.url)
                store_output_in_file(output)
            else:
                sys.exit("Error: URLs starting with 'https://' or 'http://' are not allowed.")
        elif args.ip_address:
            output = perform_mapping_scan(args.ip_address)
            store_output_in_file(output)
        else:
            sys.exit('Error: Please provide either a target IP address using the --ip-address/-ip argument or a '
                     'target URL using the --url/-u argument for mapping scan.')
    elif args.scan == 'domain':
        if args.url:
            if not ("https://" in args.url or "http://" in args.url):
                if args.dns is not None:
                    output = perform_domain_scan(args.url, args.dns)
                    store_output_in_file(output)
                else:
                    sys.exit("Error: Please provide DNS Server")
            else:
                sys.exit("Error: URLs starting with 'https://' or 'http://' are not allowed.")
        elif args.ip_address:
            if args.dns is not None:
                output = perform_domain_scan(args.ip_address, args.dns)
                store_output_in_file(output)
            else:
                sys.exit("Error: Please provide DNS Server")
        else:
            sys.exit('Error: Please provide either a target IP address using the --ip-address/-ip argument or a '
                     'target URL using the --url/-u argument for domain scan.')
    elif args.scan == 'subdomain':
        if args.url:
            if not ("https://" in args.url or "http://" in args.url):
                if args.auto:
                    output = perform_auto_subdomain_scan(args.url)
                elif args.list:
                    output = perform_custom_subdomain_scan(args.url, args.list)
                else:
                    sys.exit('Error: Please provide either the --auto or --list argument for subdomain scan.')
                store_output_in_file(output)
            else:
                sys.exit("Error: URLs starting with 'https://' or 'http://' are not allowed.")
        else:
            sys.exit('Error: Please provide a target URL using the --url/-u argument for subdomain scan.')
    elif args.version:
        display()
        print("%s█ {:<13} █ {:<50} █".format("PROJECT NAME",
                                             "SCUTUM - WEB/Server Vulnerability Detection Tool".upper()) % B)
        print("%s█ {:<13} █ {:<50} █".format("VERSION", __version__) % B)
        print("%s█ {:<13} █ {:<50} █".format("BUILD", __build__.upper()) % B)
        print("%s█ {:<13} █ {:<50} █".format("LICENCE", __license__.upper()) % B)
        print("%s█ {:<13} █ {:<50} █".format("DEVELOPED BY", "DIPEN CHAVAN @HEXDEE606".upper()) % B)
        print("%s█ {:<13} █ {:<50} █".format("TESTED BY", "SHREYAS KULKARNI @PARADOX044".upper()) % B)
        print("%s██████████████████████████████████████████████████████████████████████" % Y)
        print("%s█ {:<66} █".format("Disclaimer: Scutum is created solely for educational purposes.".upper()) % Y)
        print("%s█ {:<66} █".format("It provides a controlled environment for learning about".upper()) % Y)
        print("%s█ {:<66} █".format("website and server vulnerabilities.".upper()) % Y)
        print("%s██████████████████████████████████████████████████████████████████████" % Y)

    else:
        parser.print_help()


if __name__ == '__main__':
    display()
    main()
