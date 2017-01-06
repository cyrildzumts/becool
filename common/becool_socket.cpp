#include "becool_socket.h"



int Socket::getSocket()const
{
    return socket_fd;
}

int Socket::sock_create()
{
    socket_fd = socket(hints.ai_family,
                       hints.ai_socktype,
                       hints.ai_protocol);
    if(socket_fd == SOCKET_ERROR)
    {
        perror("sock_create()");
    }
    return socket_fd;
}


int Socket::sock_bind()
{
    if(setsockopt(socket_fd, SOL_SOCKET,
                  SO_REUSEADDR,&optval,
                  sizeof(optval)) == SOCKET_ERROR)
    {
        perror("setsockopt");
        return SOCKET_ERROR;
    }
    if(bind(socket_fd,
            hints.ai_addr,
            result->ai_addrlen) == 0)
    {
        ip = result->ai_addr->sa_data;
        break; // Success !
    }
}

int Socket::sock_listen()
{
    return listen(socket_fd, BACKLOG);
}

int Socket::sock_connect()
{
    return connect(socket_fd,
                   result->ai_addr,
                   result->ai_addrlen);
}

int Socket::sock_accept()
{

}

void Socket::sock_close()
{
    close(socket_fd);
}

int Socket::sock_send(int to_fd, char *buffer, size_t count)
{
    int ret = -1;
    if(buffer)
    {
        ret = write(to_fd, buffer, count);
    }
    return ret;
}


int Socket::sock_read(int from_fd, char *buffer, size_t count)
{
    int ret = -1;
    if(buffer)
    {
        ret = read(from_fd, buffer, count);
    }
    return ret;
}


/*****************************************************************
 * TCPSocket Implementation
 * **************************************************************/
TCPSocket::TCPSocket(const std::string &ip, const std::string &port): ip{ip}, port{port}
{

}

void TCPSocket::sock_init()
{
    Logger::log("Socket initialization ...");
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "signal" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    //port = SERVER_PORT;
    // getaddrinfo() to get a list of usable addresses
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_canonname = nullptr;
    hints.ai_addr = nullptr;
    hints.ai_next = nullptr;
    // Work with IPV4/6
    hints.ai_family = AF_UNSPEC;
    // One to One Style
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_protocol = 0;
    hints.ai_flags =  AI_PASSIVE | AI_NUMERICSERV  ;
    // we could provide a host instead of nullptr
    if(getaddrinfo( ip.c_str(),
                    port.c_str(),
                    &hints,
                    &result) != 0)
    {
        perror("getaddrinfo()");
        std::exit(EXIT_FAILURE);
    }

    Logger::log("Socket initialization ... done !");
}

int TCPSocket::sock_accept()
{
    socklen_t addrlen;
    sockaddr_storage client_addr;
    //int client_socket_fd;
    addrlen = sizeof(sockaddr_storage);
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int *client_socket_fd = nullptr;
    while(true)
    {
        client_socket_fd = new int;
        *client_socket_fd = accept(socket_fd,
                                   (sockaddr*)&client_addr,
                                   &addrlen);
        if(*client_socket_fd == -1)
        {
            perror("accept error");
            continue;
        }
        // process the client request hier
    }
}


/*****************************************************************
 * SCTPSocket Implementation
 * **************************************************************/
void SCTPSocket::sock_init()
{

    sock_create();
    (void) memset(&initmsg, 0, sizeof(struct sctp_initmsg));
    getsockopt(socket_fd, IPPROTO_SCTP, SCTP_INITMSG,
               &initmsg, sizeof(sctp_initmsg));
    initmsg.sinit_max_attempts = 1;
    initmsg.sinit_max_instreams = 0;
    initmsg.sinit_num_ostreams = 1;

    if(setsockopt(socket_fd,
               IPPROTO_SCTP,
               SCTP_INITMSG,
               &initmsg,
               sizeof(struct sctp_initmsg)) < 0)
    {
        perror("SCTP_INITMSG");
        exit (1);
    }

    getsockopt(socket_fd, IPPROTO_SCTP, SCTP_EVENTS,
               &events, sizeof(sctp_event_subscribe));
    events.sctp_shutdown_event = 1;


    if(setsockopt(socket_fd,
               IPPROTO_SCTP,
               SCTP_EVENTS,
               &events,
               sizeof(struct sctp_event_subscribe)) < 0)
    {
        perror("SCTP_EVENTS");
        exit (1);
    }

    getsockopt(socket_fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
               &heartbeat, sizeof(sctp_paddrparams));
    heartbeat.spp_flags = SPP_HB_ENABLE;
    heartbeat.spp_hbinterval = 5000;
    heartbeat.spp_pathmaxrxt = 1;

    if(setsockopt(socket_fd,
               IPPROTO_SCTP,
               SCTP_PEER_ADDR_PARAMS,
               &heartbeat,
               sizeof(struct sctp_paddrparams)) < 0)
    {
        perror("SCTP_PEER_ADDR_PARAMS");
        exit (1);
    }

    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(9012);
    sockaddr.sin_addr.s_addr = inet_addr(ip.c_str());



}

int SCTPSocket::sock_create()
{
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    return socket_fd;
}

int SCTPSocket::sock_accept()
{
}


int SCTPSocket::sock_send(int to_fd, char *buffer, size_t count)
{
}

int SCTPSocket::sock_read(int from_fd, char *buffer, size_t count)
{
    int flags = 0;
    int ret = sctp_recvmsg(from_fd,
                           buffer,
                           count,
                           nullptr,
                           0,
                           &sndrcvinfo,
                           &flags);
    return ret;
}
