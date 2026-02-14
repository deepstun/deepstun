import socket
import struct
import sys

def create_stun_binding_request():
    # STUN Message Type: Binding Request (0x0001)
    msg_type = 0x0001
    # Message Length (no attributes): 0
    msg_length = 0
    # Magic Cookie (fixed): 0x2112A442
    magic_cookie = 0x2112A442
    # Transaction ID: 12 random bytes (here we use fixed for simplicity, but should be random in real use)
    transaction_id = b'\x12\x34\x56\x78' * 3  # 12 bytes

    header = struct.pack('!HHI12s', msg_type, msg_length, magic_cookie, transaction_id)
    return header

def parse_stun_response(data):
    if len(data) < 20:
        raise ValueError("Response too short")

    msg_type, msg_length = struct.unpack('!HH', data[:4])
    if msg_type != 0x0101:  # Binding Success Response
        raise ValueError(f"Unexpected message type: 0x{msg_type:04x}")

    # Skip magic cookie and transaction ID (we don't validate them here)
    offset = 20
    while offset < len(data):
        attr_type, attr_len = struct.unpack('!HH', data[offset:offset+4])
        offset += 4
        # Pad to multiple of 4
        padded_len = (attr_len + 3) // 4 * 4
        attr_value = data[offset:offset + attr_len]

        # 0x0001 = MAPPED-ADDRESS (deprecated but often used)
        # 0x0020 = XOR-MAPPED-ADDRESS (modern)
        if attr_type == 0x0020 or attr_type == 0x0001:
            if len(attr_value) < 4:
                offset += padded_len
                continue
            family = struct.unpack('!H', attr_value[:2])[0]
            port = struct.unpack('!H', attr_value[2:4])[0]
            if attr_type == 0x0020:
                # XOR with magic cookie
                xport = port ^ 0x2112
                if family == 0x01:  # IPv4
                    ip_bytes = struct.unpack('!I', attr_value[4:8])[0]
                    xip = ip_bytes ^ 0x2112A442
                    ip = socket.inet_ntoa(struct.pack('!I', xip))
                    return ip, xport
            else:  # MAPPED-ADDRESS
                if family == 0x01:  # IPv4
                    ip = socket.inet_ntoa(attr_value[4:8])
                    return ip, port
        offset += padded_len
    raise ValueError("No MAPPED-ADDRESS or XOR-MAPPED-ADDRESS found")

def get_public_ip_port(stun_host='stun.voipbuster.com', stun_port=3478, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        request = create_stun_binding_request()
        sock.sendto(request, (stun_host, stun_port))
        data, _ = sock.recvfrom(1024)
        public_ip, public_port = parse_stun_response(data)
        return public_ip, public_port
    finally:
        sock.close()

if __name__ == '__main__':
    try:
        ip, port = get_public_ip_port()
        print(f"公网 IP: {ip}")
        print(f"公网端口: {port}")
    except Exception as e:
        print(f"获取公网地址失败: {e}", file=sys.stderr)