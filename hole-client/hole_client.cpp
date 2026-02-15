#include <winsock2.h>
#include <stdio.h>
#include <conio.h>      // 用于 _kbhit() 和 _getch()
#pragma comment(lib, "ws2_32.lib")

#define TEST_MODE_WITH_LAN_1ROUTER    1
#define TEST_MODE_WITH_LAN_2ROUTER    2
#define TEST_MODE_WITH_WAN            3

#define TEST_MODE TEST_MODE_WITH_WAN

#if TEST_MODE == TEST_MODE_WITH_LAN_1ROUTER

#define PUBLIC_TARGET_IP    "10.51.1.102"
#define PUBLIC_TARGET_PORT  0xde1e

#elif TEST_MODE == TEST_MODE_WITH_LAN_2ROUTER

#define PUBLIC_TARGET_IP    "192.168.1.31"
#define PUBLIC_TARGET_PORT  0xde1e

#elif TEST_MODE == TEST_MODE_WITH_WAN

#define PUBLIC_TARGET_IP      "27.38.213.25"
#define PUBLIC_TARGET_PORT    2646

#endif

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("socket error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    const char* target_ip = PUBLIC_TARGET_IP;
    int target_port = PUBLIC_TARGET_PORT;

    sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip);

    printf("目标地址: %s:%d\n", target_ip, target_port);
    printf("开始发送 HELLO... (按 ESC 或 'q' 退出)\n");

    int seq = 0;
    char buf[64];
    int running = 1;

    while (running) {
        // 发送 HELLO
        sprintf(buf, "HELLO #%d from OLD", seq++);
        int len = sendto(sock, buf, strlen(buf), 0,
                         (sockaddr*)&dest, sizeof(dest));
        if (len == SOCKET_ERROR) {
            printf("sendto error: %d\n", WSAGetLastError());
        } else {
            printf("已发送: %s\n", buf);
        }

        // 检查键盘输入（等待期间允许响应按键）
        // 由于 Sleep(2000) 会阻塞，我们采用短循环：每 200ms 检查一次，累计 2 秒
        for (int i = 0; i < 10; i++) {   // 10 * 200ms = 2s
            Sleep(200);
            if (_kbhit()) {               // 如果有按键
                int ch = _getch();         // 读取按键
                if (ch == 27 || ch == 'q' || ch == 'Q') { // ESC 或 q/Q
                    printf("\n用户按下退出键，程序结束。\n");
                    running = 0;
                    break;
                }
            }
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}