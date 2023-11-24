/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#ifdef __linux__

// There are several ways to play with this program. Here we just give an
// example for the simplest scenario. Let us say that a Linux box has a
// public IPv4 address on eth0. Please try the following steps and adjust
// the parameters when necessary.
//
// # Enable IP forwarding
// echo 1 > /proc/sys/net/ipv4/ip_forward
//
// # Pick a range of private addresses and perform NAT over eth0.
// iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
//
// # Create a TUN interface.
// ip tuntap add dev tun0 mode tun
//
// # Set the addresses and bring up the interface.
// ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
//
// # Create a server on port 8000 with shared secret "test".
// ./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
//
// This program only handles a session at a time. To allow multiple sessions,
// multiple servers can be created on the same port, but each of them requires
// its own TUN interface. A short shell script will be sufficient. Since this
// program is designed for demonstration purpose, it performs neither strong
// authentication nor encryption. DO NOT USE IT IN PRODUCTION!

#include <net/if.h>
#include <linux/if_tun.h>

static int get_interface(char *name)
{
    printf("get_interface\n");
    /**
     * 用于在Linux操作系统中打开一个文件或设备。
     * O_RDWR: 以读写模式（Read-Write）打开文件。
     * O_NONBLOCK: 设置非阻塞模式。如果设置了此标志，则当无法立即完成请求时，open() 将返回一个错误，而不是阻塞程序执行。
     * 该函数返回一个整数值，代表打开的文件描述符。如果打开成功，
     * 可以将其作为参数传递给其他与文件 I/O 相关的系统调用，
     * 如 read()、write() 和 close() 等。如果发生错误，
     * 例如文件不存在或者没有足够的权限访问设备，函数会返回一个负数。
     */
    int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

    // 网络接口请求结构
    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    // 创建一个tunneled类型接口，并且不应启用任何 packet information (PI) 功能
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

    // 向TUN设备发送一个 TUNSETIFF 命令，该命令要求设备使用提供的参数设置自身。
    if (ioctl(interface, TUNSETIFF, &ifr)) {
        perror("Cannot get TUN interface");
        exit(1);
    }

    return interface;
}

#else

#error Sorry, you have to implement this part by yourself.

#endif
// 总结来说，这段代码的作用是创建一个UDP套接字，并绑定到指定的端口。
// 然后，通过接收数据报文，直到接收到的数据报文与指定的secret匹配。
// 最后，将套接字连接到客户端的地址和端口，并返回套接字描述符。
static int get_tunnel(char *port, char *secret)
{
    printf("get_tunnel\n");
    // We use an IPv6 socket to cover both IPv4 and IPv6.
    // 首先，通过调用socket()函数创建一个IPv6套接字。使用AF_INET6参数表示创建一个IPv6套接字，SOCK_DGRAM参数表示创建一个数据报套接字，0表示使用默认的协议。
    // char *port = "9999";
    int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
    if (tunnel < 0) {
        perror("socket");
        return -1;
    }
    int flag = 1;
    // 设置套接字选项，通过调用setsockopt()函数来设置SO_REUSEADDR选项。这个选项允许在套接字关闭后立即重新使用相同的地址和端口。这样可以避免"Address already in use"错误。
    setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    flag = 0;
    // 设置另一个套接字选项，通过调用setsockopt()函数来设置IPV6_V6ONLY选项。这个选项用于指定是否只接受IPv6连接。将flag设置为0表示允许接受IPv4和IPv6连接。
    setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

    // Accept packets received on any local address.
    // 创建一个sockaddr_in6结构体变量addr，并将其内存清零。这个结构体用于指定绑定的地址和端口。
    // 设置addr结构体的成员变量，将sin6_family设置为AF_INET6表示IPv6地址族，将sin6_port设置为指定的端口号（通过atoi()函数将字符串转换为整数）。
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(port));

    // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
    // 使用bind()函数将套接字绑定到指定的地址和端口。
    // 由于Linux系统没有SO_REUSEPORT选项，因此使用一个循环来调用bind()函数，如果绑定失败且错误码不是EADDRINUSE（地址已被使用），则返回-1。
    // 在绑定失败时，通过usleep()函数暂停一段时间（100000微秒，即0.1秒），然后再次尝试绑定。
    printf("before bind\n");
    while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {
        printf("端口被占用，等待绑定中...\n");
        perror("bind");
        if (errno != EADDRINUSE) {
            return -1;
        }
        usleep(100000);
    }
    printf("bind success\n");

    // Receive packets till the secret matches.
    // 创建一个大小为1024字节的字符数组packet，用于接收数据报文。
    char packet[1024];
    socklen_t addrlen;
    // 使用recvfrom()函数从套接字接收数据报文，并将其存储在packet数组中。
    // recvfrom()函数的参数依次为套接字描述符tunnel，接收缓冲区packet，缓冲区大小sizeof(packet)，标志参数为0，
    // 源地址信息存储在addr结构体中，addrlen为addr结构体的大小。
    do {
        addrlen = sizeof(addr);
        int n = recvfrom(tunnel, packet, sizeof(packet), 0,
                (sockaddr *)&addr, &addrlen);
        // 检查接收到的数据报文，如果接收失败（n <= 0），则返回-1。否则，将packet数组的最后一个字节设置为0，以确保字符串以空字符结尾。
        if (n <= 0) {
            return -1;
        }
        packet[n] = 0;
        // 使用do-while循环，检查接收到的数据报文是否与指定的secret匹配。
        // 循环条件为packet[0]不等于0或者strcmp()函数比较secret和packet[1]位置开始的字符串是否相等。
        // 如果不匹配，则继续接收数据报文。
        printf("接收数据，对比密钥，数据：%s\n", &packet[1]);
    } while (packet[0] != 0 || strcmp(secret, &packet[1]));



    // Connect to the client as we only handle one client at a time.
    // 当接收到的数据报文与secret匹配时，使用connect()函数将套接字连接到客户端的地址和端口。这里假设只处理一个客户端连接。
    connect(tunnel, (sockaddr *)&addr, addrlen);
    return tunnel;
}

static void build_parameters(char *parameters, int size, int argc, char **argv)
{
    printf("build_parameters\n");
    // Well, for simplicity, we just concatenate them (almost) blindly.
    // 首先，定义一个整型变量offset，用于记录参数字符串的偏移量。
    int offset = 0;
    // 使用for循环遍历命令行参数，从第4个参数开始（即跳过前面的程序名称、端口和密钥参数）。
    for (int i = 4; i < argc; ++i) {
        // 在循环中，获取当前参数的指针和长度，并定义一个字符变量delimiter，用于指定参数之间的分隔符，默认为逗号。
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';

        // If it looks like an option, prepend a space instead of a comma.
        // 如果参数长度为2且以"-"开头，说明该参数看起来像是一个选项，此时将delimiter设置为空格，并将参数指针向后移动一位，长度减一。
        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        // This is just a demo app, really.
        // 如果参数字符串的长度加上当前偏移量超过了指定的size大小，说明参数字符串太大，打印错误信息并退出程序。
        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        // Append the delimiter and the parameter.
        // 将delimiter字符和参数字符串拷贝到parameters数组中，从偏移量offset开始。
        // 拷贝时，将delimiter放在parameters[offset]位置，然后将参数字符串拷贝到parameters[offset + 1]的位置。
        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }

    // Fill the rest of the space with spaces.
    // 循环结束后，使用memset()函数将剩余的空间填充为空格，以确保参数字符串的长度达到指定的size。
    memset(&parameters[offset], ' ', size - offset);

    // Control messages always start with zero.
    // 最后，将参数字符串的第一个字符设置为0，用于表示控制消息的起始。
    parameters[0] = 0;
}

static void printSourceIp(char * packet)
{
    printf("sourceIp: ");
    int i = 0;
    for (i = 0; i < 4; i++)
    {
        printf("%d", (unsigned char)packet[i + 12]);
        if (i != 3) {
            printf(".");
        }
    }
    printf("\n");
}

static void printDestIp(char * packet)
{
    printf("destIp: ");
    int i = 0;
    for (i = 0; i < 4; i++)
    {
        printf("%d", (unsigned char)packet[i + 16]);
        if (i != 3) {
            printf(".");
        }
    }
    printf("\n");
}

//-----------------------------------------------------------------------------

int main(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: %s <tunN> <port> <secret> options...\n"
               "\n"
               "Options:\n"
               "  -m <MTU> for the maximum transmission unit\n"
               "  -a <address> <prefix-length> for the private address\n"
               "  -r <address> <prefix-length> for the forwarding route\n"
               "  -d <address> for the domain name server\n"
               "  -s <domain> for the search domain\n"
               "\n"
               "Note that TUN interface needs to be configured properly\n"
               "BEFORE running this program. For more information, please\n"
               "read the comments in the source code.\n\n", argv[0]);
        exit(1);
    }

    // Parse the arguments and set the parameters.
    char parameters[1024];
    // 创建一个大小为1024字节的字符数组parameters，用于存储构建的参数字符串。
    build_parameters(parameters, sizeof(parameters), argc, argv);

    // Get TUN interface.
    // 调用get_interface()函数，传递argv[1]作为参数，获取TUN接口的文件描述符。
    int interface = get_interface(argv[1]);

    // Wait for a tunnel.
    int tunnel;
    // 定义一个整型变量tunnel，用于存储获取到的隧道的文件描述符。
    while ((tunnel = get_tunnel(argv[2], argv[3])) != -1) {
        printf("%s: Here comes a new tunnel\n", argv[1]);

        // On UN*X, there are many ways to deal with multiple file
        // descriptors, such as poll(2), select(2), epoll(7) on Linux,
        // kqueue(2) on FreeBSD, pthread(3), or even fork(2). Here we
        // mimic everything from the client, so their source code can
        // be easily compared side by side.

        // Put the tunnel into non-blocking mode.
        // 使用fcntl()函数，将tunnel的文件状态标志设置为O_NONBLOCK，以将其设置为非阻塞模式。
        fcntl(tunnel, F_SETFL, O_NONBLOCK);

        // Send the parameters several times in case of packet loss.
        // 使用for循环，发送参数字符串到tunnel，发送3次，每次发送使用send()函数，传递parameters、sizeof(parameters)和MSG_NOSIGNAL标志。
        for (int i = 0; i < 3; ++i) {
            send(tunnel, parameters, sizeof(parameters), MSG_NOSIGNAL);
        }

        // Allocate the buffer for a single packet.
        // 创建一个大小为32767字节的字符数组packet，用于接收数据。
        char packet[32767];

        // We use a timer to determine the status of the tunnel. It
        // works on both sides. A positive value means sending, and
        // any other means receiving. We start with receiving.
        // 定义一个整型变量timer，用于计时。
        int timer = 0;

        // We keep forwarding packets till something goes wrong.
        // 使用while循环，不断进行数据的读取和发送。
        while (true) {
            // Assume that we did not make any progress in this iteration.
            // 在循环中，首先将idle标志设置为true，表示当前没有数据传输。
            bool idle = true;

            // Read the outgoing packet from the input stream.
            // 使用read()函数从interface读取数据，将读取到的数据发送到tunnel，如果读取到数据，将idle标志设置为false，并根据timer的值更新timer。
            int length = read(interface, packet, sizeof(packet));
            // printf("Read the outgoing packet from the input stream, lenght: %d\n", length);
            if (length > 0) {
                // Write the outgoing packet to the tunnel.
                printf("从TUN设备读取数据, lenght: %d\n", length);
                printSourceIp(packet);
                printDestIp(packet);
                send(tunnel, packet, length, MSG_NOSIGNAL);

                // There might be more outgoing packets.
                idle = false;

                // If we were receiving, switch to sending.
                if (timer < 1) {
                    timer = 1;
                }
            }

            // Read the incoming packet from the tunnel.
            // 使用recv()函数从tunnel接收数据，如果接收到的数据长度为0，表示隧道已断开，跳出循环。
            length = recv(tunnel, packet, sizeof(packet), 0);
            // printf("Read the incoming packet from the tunnel, lenght: %d\n", length);
            if (length == 0) {
                break;
            }
            if (length > 0) {
                // 如果接收到的数据长度大于0，判断接收到的数据是否为控制消息（packet[0]为0），
                // 如果不是，则将数据写入到interface，将idle标志设置为false，并根据timer的值更新timer。
                // Ignore control messages, which start with zero.
                if (packet[0] != 0) {
                    // Write the incoming packet to the output stream.
                    ssize_t size = write(interface, packet, length);
                    printf("将数据写入TUN设备, lenght: %ld\n", size);
                    printSourceIp(packet);
                    printDestIp(packet);
                }
                // There might be more incoming packets.
                idle = false;

                // If we were sending, switch to receiving.
                if (timer > 0) {
                    timer = 0;
                }
            }

            // If we are idle or waiting for the network, sleep for a
            // fraction of time to avoid busy looping.
            if (idle) {
                usleep(100000);

                // Increase the timer. This is inaccurate but good enough,
                // since everything is operated in non-blocking mode.
                timer += (timer > 0) ? 100 : -100;

                // We are receiving for a long time but not sending.
                // Can you figure out why we use a different value? :)
                if (timer < -16000) {
                    // Send empty control messages.
                    packet[0] = 0;
                    for (int i = 0; i < 3; ++i) {
                        send(tunnel, packet, 1, MSG_NOSIGNAL);
                    }

                    // Switch to sending.
                    timer = 1;
                }

                // We are sending for a long time but not receiving.
                // 如果timer大于20000，表示发送数据的时间较长但没有接收数据，跳出循环。
                if (timer > 20000) {
                    break;
                }
            }
        }
        // 循环结束后，打印一条消息表示隧道已断开。
        printf("%s: The tunnel is broken\n", argv[1]);
        // 关闭tunnel的文件描述符。
        close(tunnel);
    }
    // 如果无法创建隧道，使用perror()函数打印错误信息。
    perror("Cannot create tunnels");
    exit(1);
}
