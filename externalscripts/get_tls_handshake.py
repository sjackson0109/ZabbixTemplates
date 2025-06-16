#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/03/03
Updated: 2025/05/08
Version: 2.3


Description:
    Script that is designed to test TLS handshake capabilities with a specified host or IP endpoint. It dynamically detects available SSL/TLS protocols and ciphers on the client-system, tests their compatibility, and provides a detailed report of successful and failed connections.  
Features:
    - **Dynamic Detection**: Protocols and ciphers are dynamically detected from the client system.
    - **Compatibility Filtering**: Incompatible protocol-cipher pairs are filtered out before testing.
    - **Output Formatting**: Protocols and ciphers are printed in a clean, readable format.
    - **Optional Arguments**: Port is optional with a default of `443`.
    - **Verbose Mode**: Detailed logging is available with the `--verbose` switch.
    - **Error Handling**: Errors are handled gracefully, and only shown in verbose mode.
    - **Endpoint Testing**: Each protocol-cipher pair is tested against the specified endpoint.
    - **Timeout Handling**: Includes a configurable timeout for socket connections.
    - **Cross-Platform**: Works on Linux, Windows, and is really designed to run in a Docker container (Zabbix?)
    - **New arguments for Zabbix**: Now includes --discover and --check arguments.
"""
import json
import sys
import ssl
import socket
import warnings
from argparse import ArgumentParser

protocol_map = {
    "PROTOCOL_SSLv1": "SSLv1.0",
    "PROTOCOL_SSLv2": "SSLv2.0",
    "PROTOCOL_SSLv3": "SSLv3.0",
    "PROTOCOL_TLSv1": "TLSv1.0",
    "PROTOCOL_TLSv1_1": "TLSv1.1",
    "PROTOCOL_TLSv1_2": "TLSv1.2",
    "PROTOCOL_TLSv1_3": "TLSv1.3",
}
reverse_protocol_map = {v: k for k, v in protocol_map.items()}

def get_available_protocols():
    protocols = []
    for const, name in protocol_map.items():
        try:
            if hasattr(ssl, const):
                with warnings.catch_warnings():
                    if not args.verbose:
                        warnings.filterwarnings("ignore", category=DeprecationWarning)
                    ssl.SSLContext(getattr(ssl, const))
                protocols.append(name)
                if args.verbose:
                    print(f"Protocol {name} is available.")
        except Exception as e:
            if args.verbose:
                print(f"Protocol {name} is NOT available: {e}")
    return protocols

def get_available_ciphers():
    return ssl.create_default_context().get_ciphers()

def create_criteria_array(protocols, ciphers):
    pairs = []
    for p in protocols:
        for c in ciphers:
            pairs.append((p, c["name"]))
    if args.verbose:
        print(f"Created {len(pairs)} protocol-cipher pairs.")
    return pairs

def filter_compatible_criteria(criteria):
    compatible = []
    for protocol, cipher in criteria:
        try:
            proto_const = reverse_protocol_map.get(protocol)
            if not proto_const:
                continue
            with warnings.catch_warnings():
                if not args.verbose:
                    warnings.filterwarnings("ignore", category=DeprecationWarning)
                ctx = ssl.SSLContext(getattr(ssl, proto_const))
            ctx.set_ciphers(cipher)
            compatible.append((protocol, cipher))
            if args.verbose:
                print(f"[CLIENT] Compatible: {protocol} with {cipher}")
        except Exception as e:
            if args.verbose:
                print(f"[CLIENT] Incompatible: {protocol} with {cipher} - {e}")
    return compatible


def test_endpoint(endpoint, port, protocol, cipher, timeout):
    if args.verbose:
        print(f"Testing {protocol} with {cipher} on {endpoint}:{port}")
    try:
        proto_const = reverse_protocol_map.get(protocol)
        if not proto_const or not hasattr(ssl, proto_const):
            return 2
        with warnings.catch_warnings():
            if not args.verbose:
                warnings.filterwarnings("ignore", category=DeprecationWarning)
            context = ssl.SSLContext(getattr(ssl, proto_const))
        context.set_ciphers(cipher)
        with socket.create_connection((endpoint, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=endpoint):
                return 1
    except Exception as e:
        if args.verbose:
            print(f"❌ Connection failed: {e}")
        return 0

def main():
    if args.discover:
        if args.verbose:
            print(" ------------------------------")
            print("| GET CLIENT COMPATIBILITY    |")
            print(" ------------------------------")
        protocols = get_available_protocols()
        ciphers = get_available_ciphers()
        if args.verbose:
            print("\n ------------------------------")
            print("| BUILDING A CHECKLIST        |")
            print(" ------------------------------")
        criteria = create_criteria_array(protocols, ciphers)
        compatible = []
        if args.verbose:
            print("\n ------------------------------")
            print("| EXECUTING DISCOVER           |")
            print(" ------------------------------")
        results = []
        for proto, cipher in filter_compatible_criteria(criteria):
            result = test_endpoint(args.host, args.port, proto, cipher, args.timeout)
            results.append((result, proto, cipher))
        if args.verbose:
            print("\n ------------------------------")
            print("| RESULTS                     |")
            print(" ------------------------------")
            print(f"{'STATUS':<8} {' PROTOCOL':<10} {' CIPHER'}")
            print("-" * 60)
            for status, proto, cipher in results:
                s = '✅' if status == 1 else '❌'
                print(f"{s:<8} {proto:<10} {cipher}")
        else:
            data = [{"{#PROTOCOL}": p, "{#CIPHER}": c} for r, p, c in results if r == 1]
            print(json.dumps({"data": data}, indent=4))

    elif args.check:
        if args.protocol not in get_available_protocols():
            print(2)
            return
        try:
            proto_const = reverse_protocol_map[args.protocol]
            context = ssl.SSLContext(getattr(ssl, proto_const))
            context.set_ciphers(args.cipher)
        except Exception:
            print(2)
            return
        result = test_endpoint(args.host, args.port, args.protocol, args.cipher, args.timeout)
        print(result)

    else:
        if args.verbose:
            print(" ------------------------------")
            print("| GET CLIENT COMPATIBILITY    |")
            print(" ------------------------------")
        protocols = get_available_protocols()
        ciphers = get_available_ciphers()
        if args.verbose:
            print("\n------------------------------")
            print("| BUILDING A CHECKLIST        |")
            print("------------------------------")
        criteria = create_criteria_array(protocols, ciphers)
        compatible = filter_compatible_criteria(criteria)  # Store compatible pairs
        if args.verbose:
            print("\n ------------------------------")
            print("| EXECUTING DISCOVER          |")
            print(" ------------------------------")
        results = []
        for proto, cipher in compatible:
            result = test_endpoint(args.host, args.port, proto, cipher, args.timeout)
            results.append((result, proto, cipher))
        if args.verbose:
            print("\n ------------------------------")
            print("| RESULTS                     |")
            print(" ------------------------------")
            print(f"{'STATUS':<8} {' PROTOCOL':<10} {' CIPHER'}")
            print("-" * 60)
            for status, proto, cipher in results:
                s = '✅' if status == 1 else '❌'
                print(f"{s:<8} {proto:<10} {cipher}")
        else:
            data = [{"{#PROTOCOL}": p, "{#CIPHER}": c} for r, p, c in results if r == 1]
            print(json.dumps({"data": data}, indent=4))

if __name__ == "__main__":
    import warnings
    warnings.simplefilter("ignore", category=DeprecationWarning)

    parser = ArgumentParser(description="TLS Handshake Tester with Zabbix Integration")
    parser.add_argument("host", help="Target host or IP")
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("-t", "--timeout", type=int, default=4)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-d", "--discover", action="store_true")
    parser.add_argument("-c", "--check", action="store_true")
    parser.add_argument("-k", "--protocol", help="Protocol name to check")
    parser.add_argument("-y", "--cipher", help="Cipher name to check")
    args = parser.parse_args()

    main()