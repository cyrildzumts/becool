#include "becool_socket.h"



int Socket::getSocket()const
{
    return socket_fd;
}

void Socket::sock_init(bool server)
{
    Logger::log("Socket initialization ...");
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "signal" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    memset(&self_addr, 0,sizeof(sockaddr_in));
    memset(&peer_addr, 0,sizeof(sockaddr_in));
    addrlen = sizeof(peer_addr);
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
    hints.ai_protocol = 0;
    hints.ai_flags = server ? (AI_PASSIVE | AI_NUMERICSERV ) : AI_NUMERICSERV ;
    // we could provide a host instead of nullptr
    if(getaddrinfo( ip.c_str(),
                    port.c_str(),
                    &hints,
                    &result) != 0)
    {
        perror("getaddrinfo()");
        std::exit(EXIT_FAILURE);
    }
}

int Socket::sock_create()
{
    socket_fd = socket(hints.ai_family,
                       hints.ai_socktype,
                       hints.ai_protocol);
    if(socket_fd == SOCKET_ERROR)
    {
        perror("sock_create()");
        exit(EXIT_FAILURE);
    }
    return socket_fd;
}


int Socket::sock_bind()
{
    Logger::log("binding socket to ip address ...");
    addrinfo *rp;
    int optval = 1;
    for( rp = result; rp != nullptr; rp = rp->ai_next)
    {
        socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(socket_fd == SOCKET_ERROR)
        {
            // on error we try the next address
            continue;
        }
        if(setsockopt(socket_fd, SOL_SOCKET,
                      SO_REUSEADDR,&optval,
                      sizeof(optval)) == SOCKET_ERROR)
        {
            perror("setsockopt");
            return SOCKET_ERROR;
        }
        if(bind(socket_fd,
                rp->ai_addr,
                rp->ai_addrlen) == 0)
        {
             ip = rp->ai_addr->sa_data;
             Logger::log("binding socket to ip address ... done !");
            break; // Success !
        }
        close(socket_fd);
    }
    if(rp == nullptr) // could not bind socket to any address of the list
    {
        std::cerr << "Fatal Error : couldn't find a suitable address" << std::endl;
        socket_fd = SOCKET_ERROR;
    }



    freeaddrinfo(rp);
    Logger::log("creating listening for this server ... done !");
    Logger::log("Server Connexion Info : \n"
                " ip address : " + ip + "\n"
                                        " listening port : " + port + "\n");
    return socket_fd;
}

int Socket::sock_listen()
{

    // enable socket connexions.
    // make it a socket server
    if(listen(socket_fd, BACKLOG) == SOCKET_ERROR)
    {
        perror("listen: ");
        socket_fd = SOCKET_ERROR;
    }
    Logger::log("creating listening socket for this server ... done !");
    return socket_fd;
}

int Socket::sock_connect()
{
    Logger::log("socket creation  ...");
    addrinfo *rp;
    for( rp = result; rp != nullptr; rp = rp->ai_next)
    {
        socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(socket_fd == SOCKET_ERROR)
        {
            // on error we try the next address
            continue;
        }
        Logger::log("socket created  ...");
        if(connect(socket_fd,
                   rp->ai_addr,
                   rp->ai_addrlen) != SOCKET_ERROR)
        {
            Logger::log("connexion etablished ...");
            break; // success
        }
        close(socket_fd);
    }
    if(rp == nullptr) // could not bind socket to any address of the list
    {
        std::cerr << "Fatal Error : couldn't find a suitable address" << std::endl;
        socket_fd = SOCKET_ERROR;
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(rp);
    return socket_fd;
//    return connect(socket_fd,
//                   (sockaddr*)&peer_addr,
//                   sizeof(addrlen));
}

int Socket::sock_accept()
{
    //sockaddr_in peer_addr

    return accept(socket_fd, (sockaddr*)&peer_addr, &addrlen);
}

void Socket::sock_close()
{
    close(socket_fd);
}

int Socket::sock_send( char *buffer, size_t count)
{
    int ret = -1;
    if(buffer)
    {
        ret = write(socket_fd, buffer, count);
    }
    return ret;
}


int Socket::sock_read( char *buffer, size_t count)
{
    int ret = -1;
    if(buffer)
    {
        ret = read(socket_fd, buffer, count);
    }
    return ret;
}


/*****************************************************************
 * TCPSocket Implementation
 * **************************************************************/
TCPSocket::TCPSocket(const std::string &ip, const std::string &port)
{
    this->ip = ip;
    this->port = port;
}

TCPSocket::~TCPSocket()
{
    close(socket_fd);
}

void TCPSocket::sock_init(bool server)
{
    Logger::log("Socket initialization ...");
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "signal" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    memset(&self_addr, 0,sizeof(sockaddr_in));
    memset(&peer_addr, 0,sizeof(sockaddr_in));
    addrlen = sizeof(peer_addr);
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
    hints.ai_protocol = 0;
    hints.ai_flags = server ? (AI_PASSIVE | AI_NUMERICSERV ) : AI_NUMERICSERV ;
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

// TODO Pass a function object to sock_accept
// so that it will call that function
// on a new connection
//int TCPSocket::sock_accept()
//{

//}


/*****************************************************************
 * SCTPSocket Implementation
 * **************************************************************/
SCTPSocket::SCTPSocket(const std::string &ip, const std::string &port)
{
    this->ip = ip;
    this->port = port;
}

SCTPSocket::~SCTPSocket()
{
    close(socket_fd);
}


void SCTPSocket::sock_init(bool server)
{

    Logger::log("Socket initialization ...");
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "signal" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    memset(&self_addr, 0,sizeof(sockaddr_in));
    memset(&peer_addr, 0,sizeof(sockaddr_in));
    addrlen = sizeof(peer_addr);
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
    hints.ai_protocol = IPPROTO_SCTP;
    hints.ai_flags = server ? (AI_PASSIVE | AI_NUMERICSERV ) : AI_NUMERICSERV ;
    // we could provide a host instead of nullptr
    if(getaddrinfo( ip.c_str(),
                    port.c_str(),
                    &hints,
                    &result) != 0)
    {
        perror("getaddrinfo()");
        std::exit(EXIT_FAILURE);
    }

}

int SCTPSocket::sock_create()
{
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (socket_fd == -1)
    {
        perror("sctp::sock_create()");
        exit(EXIT_FAILURE);
    }
    return socket_fd;
}



int SCTPSocket::sock_send(char *buffer, size_t count)
{
    return sctp_sendmsg(socket_fd, buffer, count, nullptr, 0,0,0,0,0,0);
}

int SCTPSocket::sock_read(char *buffer, size_t count)
{
    int flags = 0;
    int ret = sctp_recvmsg(socket_fd,
                           buffer,
                           count,
                           nullptr,
                           0,
                           &sndrcvinfo,
                           &flags);
    return ret;
}

void SCTPSocket::sctp_init()
{
    Logger::log("SCTP Socket initialization ... ");
    socklen_t len = sizeof(sctp_initmsg);
    (void) memset(&initmsg, 0, sizeof(struct sctp_initmsg));
    getsockopt(socket_fd, IPPROTO_SCTP, SCTP_INITMSG,
               &initmsg, &len );
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

    len = sizeof(sctp_event_subscribe);
    getsockopt(socket_fd, IPPROTO_SCTP, SCTP_EVENTS,
               &events, &len);
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

    len = sizeof(sctp_paddrparams);
    getsockopt(socket_fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS,
               &heartbeat, &len);
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
     Logger::log("SCTP Socket initialization ... done!");
}


int SCTPSocket::sock_bind()
{
    Logger::log("binding socket to ip address ...");
    addrinfo *rp;
    int optval = 1;
    for( rp = result; rp != nullptr; rp = rp->ai_next)
    {
        socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(socket_fd == SOCKET_ERROR)
        {
            // on error we try the next address
            continue;
        }
        if(setsockopt(socket_fd, SOL_SOCKET,
                      SO_REUSEADDR,&optval,
                      sizeof(optval)) == SOCKET_ERROR)
        {
            perror("setsockopt");
            return SOCKET_ERROR;
        }
        sctp_init();
        if(bind(socket_fd,
                rp->ai_addr,
                rp->ai_addrlen) == 0)
        {
             ip = rp->ai_addr->sa_data;
             Logger::log("binding socket to ip address ... done !");
            break; // Success !
        }
        close(socket_fd);
        this->sock_create();
    }
    if(rp == nullptr) // could not bind socket to any address of the list
    {
        std::cerr << "Fatal Error : couldn't find a suitable address" << std::endl;
        socket_fd = SOCKET_ERROR;
    }



    freeaddrinfo(rp);
    Logger::log("creating listening for this server ... done !");
    Logger::log("Server Connexion Info : \n"
                " ip address : " + ip + "\n"
                                        " listening port : " + port + "\n");
    return socket_fd;
}

