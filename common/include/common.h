#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/select.h>
#include <linux/socket.h>
#include <netinet/sctp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <cstring>
#include <stdio.h>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <chrono>
#include <map>
#include <functional>


#define SERVER_PORT "50000"
//#define SERVER_PORT "9012"
//#define SERVER_IP "141.22.27.107"
#define SERVER_IP "localhost"
#define BACKLOG 50
#define SOCKET_ERROR -1
#define BUFFER_SIZE 1024

#define LEN 30

enum SERVER_SERVICE
{
    LOGIN,
    LOGOUT,
    SENDMSG,
    GETUSERS,
    HEARTBEAT,
};

struct NeighboorServer
{
    std::string host;
    std::string port;
};

#endif // COMMON_H
