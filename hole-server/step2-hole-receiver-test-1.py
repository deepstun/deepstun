import socket
import random
import struct
import time

# ---------- STUN 函数 ----------
def stun_get_mapped_addr(sock, stun_server, stun_port):
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

    # 临时设为超时模式
    sock.settimeout(2)
    try:
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        return None
    finally:
        # 关键修复：恢复为非阻塞模式，而不是 None
        sock.setblocking(False)

    # 解析响应（不变）
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
            if family == 0x01:  # IPv4
                port = struct.unpack('>H', attr_value[2:4])[0]
                ip = socket.inet_ntoa(attr_value[4:8])
                return (ip, port)
    return None


def is_stun_response(data):
    """快速判断是否为 STUN Binding Response"""
    if len(data) < 20:
        return False
    # STUN 响应类型为 0x0101，Magic Cookie 为 0x2112A442
    msg_type, msg_len, magic = struct.unpack('>HHI', data[:8])
    return msg_type == 0x0101 and magic == 0x2112A442

def parse_stun_response(data):
    """从 STUN 响应中提取 MAPPED-ADDRESS，返回 (ip, port) 或 None"""
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


# ---------- 主程序 ----------
LOCAL_PORT = 0xde1e          # 56862
STUN_SERVER = "stun.voipbuster.com"
STUN_PORT = 3478
KEEPALIVE_INTERVAL = 25      # 秒，定期刷新 STUN 以保持 NAT 映射

# 创建 socket 并绑定本地端口
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', LOCAL_PORT))
sock.setblocking(False)      # 非阻塞，方便同时处理接收和定时任务

print(f"[信息] 本地绑定端口: {LOCAL_PORT}")
print("[信息] 正在获取公网地址...")

# 首次获取公网地址
external = stun_get_mapped_addr(sock, STUN_SERVER, STUN_PORT)
if not external:
    print("[错误] 无法获取公网地址，退出")
    sock.close()
    exit(1)

print(f"[成功] 公网地址: {external[0]}:{external[1]}")
print("[信息] 开始监听，等待来自 OLD 的 HELLO...")

last_stun = time.time()
# 主循环
try:
    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except BlockingIOError:
            pass
        else:
            # 先判断是否为 STUN 响应
            if is_stun_response(data):
                mapped = parse_stun_response(data)
                if mapped:
                    if mapped != external:
                        print(f"[注意] 公网地址已变更为 {mapped[0]}:{mapped[1]}")
                        external = mapped
                    else:
                        # 可能是迟到的重复响应，忽略或打印调试
                        print("[信息] 收到迟到的 STUN 响应，地址未变")
                else:
                    print("[警告] 收到无效 STUN 响应")
            else:
                # 非 STUN 响应，当作 HELLO 处理
                try:
                    message = data.decode('utf-8')
                except UnicodeDecodeError:
                    message = repr(data)  # 原始字节显示
                print(f"[收到] 来自 {addr} : {message}")

        # 定时刷新 STUN（保持不变）
        now = time.time()
        if now - last_stun > KEEPALIVE_INTERVAL:
            new_ext = stun_get_mapped_addr(sock, STUN_SERVER, STUN_PORT)
            if new_ext:
                if new_ext != external:
                    print(f"[注意] 公网地址已变更为 {new_ext[0]}:{new_ext[1]}")
                    external = new_ext
                else:
                    print("[信息] STUN 刷新成功")
            else:
                print("[警告] STUN 刷新失败")
            last_stun = now

        time.sleep(0.1)
except KeyboardInterrupt:
    print("\n[信息] 用户中断，退出程序")
finally:
    sock.close()