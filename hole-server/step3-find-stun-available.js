import socket
import random
import struct

def stun_get_mapped_addr(stun_server, stun_port, local_port=0xde1e):
    """
    向 STUN 服务器发送 Binding Request，返回 (公网IP, 公网端口) 或 None
    """
    # 第一步：解析 STUN 服务器地址（处理域名 -> IP）
    try:
        resolved_ip = socket.gethostbyname(stun_server)
        print(f"[DNS] 解析 {stun_server} -> {resolved_ip}")
    except socket.gaierror as e:
        print(f"[错误] 无法解析服务器地址 {stun_server}: {e}")
        return None

    # 创建 UDP socket 并绑定到指定的本地端口
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', local_port))

    # 构造 STUN Binding Request 头部
    msg_type = 0x0001                     # Binding Request
    msg_len = 0                            # 不带属性
    magic_cookie = 0x2112A442
    transaction_id = bytes(random.getrandbits(8) for _ in range(12))
    header = struct.pack('>HHI', msg_type, msg_len, magic_cookie) + transaction_id

    try:
        # 发送请求（使用解析后的 IP）
        sock.sendto(header, (resolved_ip, stun_port))
        print(f"[发送] 向 {resolved_ip}:{stun_port} 发送 Binding Request")

        # 等待响应（设置3秒超时）
        sock.settimeout(3)
        data, addr = sock.recvfrom(1024)
        print(f"[接收] 从 {addr} 收到 {len(data)} 字节响应")
        # 恢复阻塞模式（可选，不影响后续）
        sock.settimeout(None)

        # ---------- 解析响应 ----------
        if len(data) < 20:
            print("[错误] 响应数据太短")
            return None

        rsp_type, rsp_len, rsp_cookie = struct.unpack('>HHI', data[:8])
        if rsp_type != 0x0101:                     # Binding Success Response
            print(f"[错误] 不是成功的响应，消息类型: 0x{rsp_type:04x}")
            return None
        if rsp_cookie != magic_cookie:
            print("[错误] Magic Cookie 不匹配")
            return None
        rsp_trans_id = data[8:20]
        if rsp_trans_id != transaction_id:
            print("[错误] 事务 ID 不匹配")
            return None

        # 遍历属性，查找 MAPPED-ADDRESS (类型 0x0001)
        pos = 20
        while pos + 4 <= len(data):
            attr_type, attr_len = struct.unpack('>HH', data[pos:pos+4])
            pos += 4
            attr_value = data[pos:pos+attr_len]
            pos += attr_len
            # 属性长度按4字节对齐
            padding = (4 - (attr_len % 4)) % 4
            pos += padding

            if attr_type == 0x0001:  # MAPPED-ADDRESS
                if len(attr_value) < 8:
                    continue
                family = attr_value[1]
                if family == 0x01:   # IPv4
                    port = struct.unpack('>H', attr_value[2:4])[0]
                    ip = socket.inet_ntoa(attr_value[4:8])
                    return (ip, port)

        print("[错误] 响应中未找到 MAPPED-ADDRESS 属性")
        return None

    except socket.timeout:
        print("[错误] 请求超时，请检查网络或更换 STUN 服务器")
        return None
    except Exception as e:
        print(f"[错误] 发生未知异常: {e}")
        return None
    finally:
        # 确保套接字被关闭
        sock.close()


if __name__ == '__main__':

    # STUN_SERVER = "stun.qq.com"      # 使用域名，会自动解析
    # STUN_SERVER = "stun.voipbuster.com"
    # STUN_SERVER = "stun.stunprotocol.org"
    # STUN_SERVER = "stun.miwifi.com"
    STUN_SERVER = "stun.chat.bilibili.com"
    STUN_PORT = 3478
    LOCAL_PORT = 0xde1e               # 57054

    mapped = stun_get_mapped_addr(STUN_SERVER, STUN_PORT, LOCAL_PORT)
    if mapped:
        print("\n=== 成功获取公网地址 ===")
        print(f"IP: {mapped[0]}")
        print(f"端口: {mapped[1]}")
        print(f"完整地址: {mapped[0]}:{mapped[1]}")
    else:
        print("\n获取公网地址失败，请尝试以下操作：")
        print("1. 检查网络连接是否正常")
        print("2. 更换 STUN 服务器，例如：")
        print("   - stun.l.google.com:19302")
        print("   - stun.stunprotocol.org:3478")
        print("   - stun.voipbuster.com:3478")
        print("3. 暂时关闭 Windows 防火墙测试")
        print("4. 如果 DNS 解析成功但请求超时，可能是服务器临时不可达，多试几次或换一个")