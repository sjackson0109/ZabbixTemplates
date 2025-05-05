#!/usr/bin/env python3
"""
Author: Simon Jackson (sjackson0109)
Created: 2025/04/24
Updated: 2025/04/24
Version: 1.0
Note:  NOT YET OPERATIONAL
Description:
    Script that is designed to allow for the execution of SNMP GET/SET/WALK commands, via the Zabbix UI, without the need to install snmptools.
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
#!/usr/bin/env python3

import socket
import struct
import argparse
import random

class SimpleSNMPClient:
    def __init__(self, host, port=161, community='public', timeout=2):
        self.host = host
        self.port = port
        self.community = community.encode()
        self.timeout = timeout

    def get(self, oid):
        """Perform SNMP GET request"""
        try:
            # Convert OID string to tuple of integers
            oid_parts = tuple(map(int, oid.split('.')))
            
            # Create SNMP GET request packet
            packet = self._build_get_packet(oid_parts)
            
            # Send and receive
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(packet, (self.host, self.port))
                response, _ = sock.recvfrom(65535)
            
            # Parse response
            return self._parse_response(response)
        except socket.timeout:
            return "Error: SNMP request timed out"
        except Exception as e:
            return f"Error: {str(e)}"

    def _build_get_packet(self, oid):
        """Build SNMP GET request packet (v2c)"""
        # Generate a random request ID within signed 32-bit range
        request_id = random.randint(1, 2147483647)
        
        # Build OID part
        oid_bytes = self._encode_oid(oid)
        
        # Build variable bindings
        var_bind = b'\x30' + self._ber_len(
            b'\x06' + self._ber_len(oid_bytes) + oid_bytes +  # OID
            b'\x05\x00'  # NULL value
        )
        
        # Build PDU
        pdu = b'\xa0' + self._ber_len(
            self._encode_integer(request_id) +  # Request ID
            b'\x02\x01\x00' +  # Error status (0)
            b'\x02\x01\x00' +  # Error index (0)
            var_bind
        )
        
        # Build full message
        message = b'\x30' + self._ber_len(
            b'\x02\x01\x01' +  # SNMP version (1 = v2c)
            b'\x04' + self._ber_len(self.community) + self.community +
            pdu
        )
        
        return message

    def _encode_integer(self, value):
        """Encode integer to BER format"""
        if value == 0:
            return b'\x02\x01\x00'
        
        # Determine how many bytes we need
        byte_count = 0
        temp = abs(value)
        while temp > 0:
            temp >>= 8
            byte_count += 1
        
        # Handle negative numbers
        if value < 0:
            mask = 0xff << ((byte_count) * 8 - 1)
            if (value & mask) == 0:
                byte_count += 1
        
        # Pack the integer
        bytes_val = value.to_bytes(byte_count, byteorder='big', signed=True)
        return b'\x02' + self._ber_len(bytes_val) + bytes_val

    def _encode_oid(self, oid_parts):
        """Encode OID to BER format"""
        oid_bytes = bytearray()
        # First two parts are special (1.3)
        first_two = oid_parts[0] * 40 + oid_parts[1]
        oid_bytes.append(first_two)
        
        # Encode remaining parts
        for part in oid_parts[2:]:
            if part == 0:
                oid_bytes.append(0)
            else:
                buf = bytearray()
                while part > 0:
                    buf.insert(0, (part & 0x7f) | (0x80 if len(buf) > 0 else 0))
                    part >>= 7
                oid_bytes.extend(buf)
        
        return bytes(oid_bytes)

    def _ber_len(self, data):
        """Encode BER length"""
        length = len(data)
        if length < 0x80:
            return bytes([length])
        else:
            len_bytes = []
            while length > 0:
                len_bytes.insert(0, length & 0xff)
                length >>= 8
            return bytes([0x80 | len(len_bytes)] + len_bytes)

    def _parse_response(self, data):
        """Parse SNMP response"""
        try:
            if not data.startswith(b'\x30'):
                return "Invalid SNMP response format"
            
            # Skip header and version
            pos = 2
            community_len = data[pos+1]
            pos += 2 + community_len
            
            # Check PDU type (should be 0xA2 for GetResponse)
            if data[pos] != 0xA2:
                return "Not a GET response"
            
            # Skip to variable bindings
            pos += 2  # Skip PDU header
            pos += 6  # Skip request ID, error status, error index
            
            # Parse variable bindings
            if data[pos] != 0x30:
                return "Invalid variable bindings"
            
            pos += 2  # Skip sequence header
            
            # Parse single variable binding
            if data[pos] != 0x30:
                return "Invalid variable binding"
            
            pos += 2  # Skip binding header
            
            # Skip OID
            oid_len = data[pos+1]
            pos += 2 + oid_len
            
            # Get value type and length
            value_type = data[pos]
            value_len = data[pos+1]
            value = data[pos+2:pos+2+value_len]
            
            if value_type == 0x04:  # OctetString
                return value.decode('latin-1')
            elif value_type == 0x02:  # Integer
                return str(int.from_bytes(value, byteorder='big', signed=True))
            elif value_type == 0x06:  # OID
                return '.'.join(str(b) for b in value)
            elif value_type == 0x40:  # IPAddress
                return '.'.join(str(b) for b in value)
            else:
                return f"Unsupported type {value_type}: {value.hex()}"
            
        except Exception as e:
            return f"Error parsing response: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description='Minimal SNMP Client')
    parser.add_argument('operation', choices=['get'], help='SNMP operation (only GET supported)')
    parser.add_argument('host', help='Host IP address')
    parser.add_argument('oid', help='SNMP OID')
    parser.add_argument('-p', '--port', type=int, default=161, help='SNMP port (default: 161)')
    parser.add_argument('-c', '--community', default='public', help='SNMP community string (default: public)')
    parser.add_argument('-v', '--version', choices=['2c'], default='2c', help='SNMP version (only 2c supported)')
    
    args = parser.parse_args()
    
    if args.operation == 'get':
        client = SimpleSNMPClient(args.host, args.port, args.community)
        result = client.get(args.oid)
        print(result)
    else:
        print("Only GET operation is supported in this minimal version")

if __name__ == '__main__':
    main()