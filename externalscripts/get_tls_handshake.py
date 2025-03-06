#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/03/03
Updated: 2025/03/06
Version: 2.0
Description:
    Script that is designed to test TLS handshake capabilities with a specified host or IP endpoint. It dynamically detects available SSL/TLS protocols and ciphers on the client-system, tests their compatibility, and provides a detailed report of successful and failed connections.  
Features:
    - **Dynamic Detection**: Protocols and ciphers are dynamically detected from the client system.
    - **Compatibility Filtering**: Incompatible protocol-cipher pairs are filtered out before testing.
    - **Output Formatting**: Protocols and ciphers are printed in a clean, readable format.
    - **Optional Arguments**: Port is optional with a default of `443`.
    - **Debug Mode**: Detailed logging is available with the `--debug` switch.
    - **Error Handling**: Errors are handled gracefully, and only shown in debug mode.
    - **Endpoint Testing**: Each protocol-cipher pair is tested against the specified endpoint.
    - **Timeout Handling**: Includes a configurable timeout for socket connections.
    - **Cross-Platform**: Works on Linux, Windows, and is really designed to run in a Docker container (Zabbix?)
"""
import sys
import ssl
import socket
import warnings
from argparse import ArgumentParser

def get_available_protocols():
    """Dynamically detect all available SSL/TLS protocols from the ssl module."""
    available_protocols = []
    # Define a mapping of protocol constants to their display names
    protocol_map = {
        "PROTOCOL_SSLv1": "SSLv1.0",
        "PROTOCOL_SSLv2": "SSLv2.0",
        "PROTOCOL_SSLv3": "SSLv3.0",
        "PROTOCOL_TLSv1": "TLSv1.0",
        "PROTOCOL_TLSv1_1": "TLSv1.1",
        "PROTOCOL_TLSv1_2": "TLSv1.2",
        "PROTOCOL_TLSv1_3": "TLSv1.3",
    }
    for protocol_constant, protocol_name in protocol_map.items():
        try:
            # Check if the protocol constant exists in the ssl module
            if hasattr(ssl, protocol_constant):
                # Create an SSL context to verify the protocol is usable
                with warnings.catch_warnings():
                    if not args.debug:
                        warnings.filterwarnings("ignore", category=DeprecationWarning)
                    context = ssl.SSLContext(getattr(ssl, protocol_constant))
                available_protocols.append(protocol_name)
                if args.debug:
                    print(f"Protocol {protocol_name} is available.")
        except Exception as e:
            if args.debug:
                print(f"Protocol {protocol_name} is NOT available: {e}")
    return available_protocols

def get_available_ciphers():
    """Dynamically query available ciphers on the system."""
    context = ssl.create_default_context()
    return context.get_ciphers()

def create_criteria_array(protocols, ciphers):
    """Create a CRITERIA array by joining protocols and ciphers."""
    criteria = []
    for protocol in protocols:
        for cipher in ciphers:
            criteria.append((protocol, cipher['name']))
    if args.debug:
        print(f"Created CRITERIA array with {len(criteria)} protocol-cipher pairs.")
    return criteria

def filter_compatible_criteria(criteria):
    """Filter out incompatible protocol-cipher pairs."""
    compatible_criteria = []
    for protocol, cipher in criteria:
        try:
            # Convert protocol name to constant (e.g., "TLSv1.2" -> "PROTOCOL_TLSv1_2")
            protocol_constant = {
                "SSLv1.0": "PROTOCOL_SSLv1",
                "SSLv2.0": "PROTOCOL_SSLv2",
                "SSLv3.0": "PROTOCOL_SSLv3",
                "TLSv1.0": "PROTOCOL_TLSv1",
                "TLSv1.1": "PROTOCOL_TLSv1_1",
                "TLSv1.2": "PROTOCOL_TLSv1_2",
                "TLSv1.3": "PROTOCOL_TLSv1_3",
            }.get(protocol, None)
            if protocol_constant is None:
                raise ValueError(f"Unsupported protocol: {protocol}")
            # Suppress DeprecationWarning unless debug is enabled
            with warnings.catch_warnings():
                if not args.debug:
                    warnings.filterwarnings("ignore", category=DeprecationWarning)
                context = ssl.SSLContext(getattr(ssl, protocol_constant))
            # Set the cipher and check compatibility
            context.set_ciphers(cipher)
            compatible_criteria.append((protocol, cipher))
            if args.debug:
                print(f"Added compatible pair: {protocol} with {cipher}")
        except (ssl.SSLError, ValueError, AttributeError) as e:
            if args.debug:
                print(f"Compatibility error: {protocol} with {cipher} - {e}")
    if args.debug:
        print(f"Filtered {len(compatible_criteria)} compatible protocol-cipher pairs.")
    return compatible_criteria

def test_endpoint(endpoint, port, protocol, cipher, timeout):
    """Test a specific endpoint with a given protocol and cipher."""
    try:
        # Convert protocol name to constant (e.g., "TLSv1.2" -> "PROTOCOL_TLSv1_2")
        protocol_constant = {
            "SSLv1.0": "PROTOCOL_SSLv1",
            "SSLv2.0": "PROTOCOL_SSLv2",
            "SSLv3.0": "PROTOCOL_SSLv3",
            "TLSv1.0": "PROTOCOL_TLSv1",
            "TLSv1.1": "PROTOCOL_TLSv1_1",
            "TLSv1.2": "PROTOCOL_TLSv1_2",
            "TLSv1.3": "PROTOCOL_TLSv1_3",
        }.get(protocol, None)
        if protocol_constant is None:
            raise ValueError(f"Unsupported protocol: {protocol}")
        # Suppress DeprecationWarning unless debug is enabled
        with warnings.catch_warnings():
            if not args.debug:
                warnings.filterwarnings("ignore", category=DeprecationWarning)
            context = ssl.SSLContext(getattr(ssl, protocol_constant))
        context.set_ciphers(cipher)
        # Create a socket connection and wrap it with SSL
        with socket.create_connection((endpoint, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=endpoint) as ssock:
                if args.debug:
                    print(f"Successfully connected using {protocol} with {cipher}")
                return True
    except Exception as e:
        if args.debug:
            print(f"Connection error: {protocol} with {cipher} - {e}")
        return False

def main():
    """Main function to execute the script."""
    print("Testing Capabilities:")
    # Step 1: Get available protocols
    protocols = get_available_protocols()
    print(f" Protocols: {', '.join(protocols)}")

    # Step 2: Get available ciphers
    ciphers = get_available_ciphers()
    print(f" Ciphers: {':'.join(cipher['name'] for cipher in ciphers)}")

    # Step 3: Create CRITERIA array
    criteria = create_criteria_array(protocols, ciphers)
    print("-" * 40)
    print(" ")
    # Step 4: Filter incompatible protocol-cipher pairs
    compatible_criteria = filter_compatible_criteria(criteria)

    # Step 5: Create RESULTS array
    results = []
    for protocol, cipher in compatible_criteria:
        results.append(['', protocol, cipher])

    # Step 6: Test each protocol-cipher pair
    for i, (protocol, cipher) in enumerate(compatible_criteria):
        status = test_endpoint(args.host, args.port, protocol, cipher, args.timeout)
        results[i][0] = '✅' if status else '❌'

    # Step 8: Sort RESULTS array
    results.sort(key=lambda x: (x[0], x[1], x[2]))

    # Step 9: Print RESULTS array as columns
    print("\nRESULTS:")
    print(f"{'STATUS':<8} {'PROTOCOL':<10} {'CIPHER'}")
    print("-" * 40)
    for status, protocol, cipher in results:
        print(f"{status:<8} {protocol:<10} {cipher}")

if __name__ == "__main__":
    parser = ArgumentParser(description="Check TLS handshake capabilities for a given host and port.")
    parser.add_argument("host", help="The hostname or IP address to check.")
    parser.add_argument("-p", "--port", type=int, default=443, help="The port number to check (default: 443).")
    parser.add_argument("--timeout", type=int, default=4, help="Timeout for socket connection in seconds (default: 4).")
    parser.add_argument("--debug", action="store_true", help="Enable debug output, including errors.")
    args = parser.parse_args()

    main()