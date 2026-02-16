import socket
import random
import struct
import time

def stun_get_mapped_addr(sock, stun_server, stun_port):
    """发送 STUN 请求并返回 (公网IP, 公网端口) 或 None"""
    try:
        resolved_ip = socket.gethostbyname(stun_server)
    except socket.gaierror:
        return None
    # 构造请求
    msg_type = 0x0001
    msg_len = 0
    magic_cookie = 0x2112A442
    transaction_id = bytes(random.getrandbits(8) for _ in range(12))
    header = struct.pack('>HHI', msg_type, msg_len, magic_cookie) + transaction_id
    sock.sendto(header, (resolved_ip, stun_port))
    sock.settimeout(3)
    try:
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        return None
    finally:
        sock.settimeout(None)
    # 解析响应（简化版）
    if len(data) < 20:
        return None
    pos = 20
    while pos + 4 <= len(data):
        attr_type, attr_len = struct.unpack('>HH', data[pos:pos+4])
        pos += 4
        attr_value = data[pos:pos+attr_len]
        pos += (attr_len + 3) & ~3
        if attr_type == 0x0001 and len(attr_value) >= 8:
            family = attr_value[1]
            if family == 0x01:
                port = struct.unpack('>H', attr_value[2:4])[0]
                ip = socket.inet_ntoa(attr_value[4:8])
                return (ip, port)
    return None

def detect_nat_mapping():
    LOCAL_PORT = 0xde1e  # 固定端口
    SERVERS = [
        ("stun.voipbuster.com", 3478),
        ("stun.miwifi.com", 3478)
        # ("stun.voipbuster.com", 3478),
        # ("stun.miwifi.com", 3478),
        # ("stun.voipbuster.com", 3478),
        # ("stun.miwifi.com", 3478)
    ]
    # 创建 socket 并绑定
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', LOCAL_PORT))
    sock.settimeout(3)  # 临时阻塞模式，方便处理

    results = []
    for server, port in SERVERS:
        print(f"测试 {server}:{port} ...")
        addr = stun_get_mapped_addr(sock, server, port)
        if addr:
            print(f"  公网地址: {addr[0]}:{addr[1]}")
            results.append(addr)
        else:
            print("  失败")
        # 等待几秒，避免 NAT 映射快速变化
        time.sleep(2)

    sock.close()

    if len(results) == 2:
        ip1, port1 = results[0]
        ip2, port2 = results[1]
        print("\n=== 检测结果 ===")
        if port1 == port2:
            print("✅ 公网端口相同 → 映射行为为 Endpoint Independent（锥型 NAT）")
            print("   UDP 打洞成功可能性高。")
        else:
            print("❌ 公网端口不同 → 映射行为为 Endpoint Dependent（可能为对称 NAT）")
            print("   直接打洞困难，可能需要端口预测或中继。")
    else:
        print("测试不完整，请检查网络或更换服务器。")

if __name__ == "__main__":
    detect_nat_mapping()