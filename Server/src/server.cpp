#include "../include/server.h"

Server::Server():Server(SERVER_IP, SERVER_PORT)
{

}

Server::Server(const std::string &ip, const std::string &port): ip{ip}, port{port}
{
    stopped = false;
    name = "Server";
    user_list_changed = false;
    sock = new TCPSocket(ip, port);
    //sock = new SCTPSocket(ip, port);

}

void Server::init()
{
//    Logger::log("Server initializing ...");
//    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
//    {
//        std::cerr << "signal" << std::endl;
//        std::exit(EXIT_FAILURE);
//    }

//    //port = SERVER_PORT;
//    // getaddrinfo() to get a list of usable addresses
//    memset(&hints, 0, sizeof(struct addrinfo));
//    hints.ai_canonname = nullptr;
//    hints.ai_addr = nullptr;
//    hints.ai_next = nullptr;
//    // Work with IPV4/6
//    hints.ai_family = AF_UNSPEC;
//    // One to One Style
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_protocol = IPPROTO_SCTP;
//    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV  ;
//    // we could provide a host instead of nullptr
//    if(getaddrinfo( ip.c_str(),
//                    port.c_str(),
//                    &hints,
//                    &result) != 0)
//    {
//        perror("getaddrinfo()");
//        std::exit(EXIT_FAILURE);
//    }
//    listening_socket = create_socket();
//    if(listening_socket < 0)
//    {
//        std::cerr << " a server socket couldn't be created."
//                  << std::endl;
//        exit(EXIT_FAILURE);
//    }
//    Logger::log("Server initializing ... done !");

    sock->sock_init(true);
}

int Server::create_socket()
{
//    Logger::log("creating listening for this server ...");
//    int socket_fd = -1;
//    addrinfo *rp;
//    int optval = 1;
//    for( rp = result; rp != nullptr; rp = rp->ai_next)
//    {
//        socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
//        if(socket_fd == SOCKET_ERROR)
//        {
//            // on error we try the next address
//            continue;
//        }
//        if(setsockopt(socket_fd, SOL_SOCKET,
//                      SO_REUSEADDR,&optval,
//                      sizeof(optval)) == SOCKET_ERROR)
//        {
//            perror("setsockopt");
//            return SOCKET_ERROR;
//        }
//        if(bind(socket_fd,
//                rp->ai_addr,
//                rp->ai_addrlen) == 0)
//        {
//            ip = rp->ai_addr->sa_data;
//            break; // Success !
//        }
//        close(socket_fd);
//    }
//    if(rp == nullptr) // could not bind socket to any address of the list
//    {
//        std::cerr << "Fatal Error : couldn't find a suitable address" << std::endl;
//        socket_fd = SOCKET_ERROR;
//    }

//    // enable socket connexions.
//    // make it a socket server
//    else if(listen(socket_fd, BACKLOG) == SOCKET_ERROR)
//    {
//        perror("listen: ");
//        socket_fd = SOCKET_ERROR;
//    }

//    freeaddrinfo(rp);
//    connectToServers();
//    Logger::log("creating listening for this server ... done !");
//    Logger::log("Server Connexion Info : \n"
//                " ip address : " + ip + "\n"
//                                        " listening port : " + port + "\n");
//    return socket_fd;

    sock->sock_bind();
    return sock->sock_listen();
}

void Server::start()
{
    Logger::log("Server started ...");
    socklen_t addrlen;
    sockaddr_storage client_addr;
    //int client_socket_fd;
    addrlen = sizeof(sockaddr_storage);
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int *client_socket_fd = nullptr;
    std::thread userlist_updater{&Server::update_local_list, this};
    userlist_updater.detach();
    while(!stopped)
    {
        client_socket_fd = new int;
        Logger::log("waiting for new Connexion ...");
        //*client_socket_fd = accept(listening_socket, (sockaddr*)&client_addr, &addrlen);
         *client_socket_fd = sock->sock_accept();
        if(*client_socket_fd == -1)
        {
            perror("accept error");
            continue;
        }
        Logger::log("New Connection ...");
        std::thread worker{&Server::client_handler,this, *client_socket_fd};
        worker.detach();
        client_socket_fd = nullptr;
    }
}

void Server::addClient(User *client)
{
    while(client_shield.try_lock())
    {

    }
    local_clients.push_back(client);
    client_shield.unlock();

}


User* Server::getClient(const std::string &username)
{

    User *client = nullptr;
    for(User* clt : local_clients)
    {
        if(clt->getUsername() == username)
        {
            client = clt;
            break;
        }

    }
    return client;
}

User* Server::getClient(int uid)
{
    User *client = nullptr;
    for(User* clt : local_clients)
    {
        if(clt->getUid() == uid)
        {
            client = clt;
            break;
        }

    }
    return client;
}

void Server::update_userlist(const ControlInfo &info, int sender_uid)
{
    Logger::log(std::string(__PRETTY_FUNCTION__) + " new userlist received");
    std::string user;
    RemoteEntry re ;
    for(int i = 0; i < info.header.length; i++)
    {
        user = info.entries[i].username;
        auto local = std::find_if(local_clients.begin(), local_clients.end(),
                                  [&user](User *client){
                return client->getUsername() == user ;
    } );
        if(local == local_clients.end())
        {

            auto entry = remote_clients.find(user);
            if(entry == remote_clients.end())
            {
                re.setUsername(user);
                re.setHops(info.entries[i].hops +1);
                re.setUid(sender_uid);
                remote_clients[user] = re;
                user_list_changed = true;
            }
            else
            {
                if( info.entries[i].hops < entry->second.getHops() )
                {
                    remote_clients[user].setHops(info.entries[i].hops +1);
                    remote_clients[user].setUid(sender_uid);
                }
                user_list_changed = false;
            }
        }


    }
    print_userlist();
}


void Server::update_local_list()
{
    /*
    char beat = 1;
    auto predicate = [&, this](User *client){
        if(client)
        {
            if(client->isGone())
            {
                Logger::log(client->getUsername() + " left");
                if(client->getUsername() == "")
                {
                    this->removeServer(client->getUid());
                }
            }
            return client->isGone();
        }
        return false;
    };
    Logger::log(std::string(__FUNCTION__) + " started ...");
    while(!stopped)
    {
        std::this_thread::sleep_for(ms(30000));
        auto it_new_end =
                std::remove_if(local_clients.begin(), local_clients.end(),predicate);

        local_clients.erase(it_new_end, local_clients.end());
        sendControlInfo();

        //std::this_thread::sleep_for(ms(15000));

        // heartbeat signal
        std::for_each(local_clients.begin(), local_clients.end(),
                      [&beat](User* client){
            if(write(client->getSocket(), &beat, 1) < 0)
            {
                client->setGone();

            }
        });

    }
    */

}


int Server::removeClient(User *client)
{
    int ret = -1;
    if(client)
    {
        client_shield.lock();
        client->setGone();
        client_shield.unlock();
        ret = 0;
    }

    return ret;
}



void Server::removeServer(int server_uid)
{
    //std::lock_guard<std::mutex> lock(server_shield);
    Logger::log(__PRETTY_FUNCTION__);
    for( auto it = remote_clients.begin(); it != remote_clients.end();)
    {
        if(it->second.getUid() == server_uid)
        {
            Logger::log("user " + it->second.getUsername() + " removed");
            it = remote_clients.erase(it);
            user_list_changed = true;
        }
        else
        {
            Logger::log("user " + it->second.getUsername() + " removed");
            it++;
        }
    }

}


int Server::sendToClient(int client_uid, void *data, int n)
{

    Logger::log("Client handler started");
    int count = 0;
    User *client = getClient(client_uid);
    if(client)
    {
        count = write(client->getSocket(), data, n);
        if(count < 0)
        {
            perror("SendToClient : ");
            client->setGone();

            close(client->getSocket());
        }
        else if(count < n)
        {
            Logger::log("SendToClient : Not all data could be sent");
        }
    }

    return count;
}

void Server::client_handler(int socket_fd)
{
    User client{socket_fd};
    addClient(&client);
    int count = 0;
    char buffer[BUFFER_SIZE] = {0};
    while(!client.isGone())
    {
        count = read(socket_fd, buffer, BUFFER_SIZE);
        if(count <= 0)
        {
            client.setGone();
        }
        else
        {
            if (count > 0)
            {
                print_raw_data(buffer, count);
                if(decode_and_process(buffer,
                                      client.getUid()) == -1)
                {
                    client.setGone();
                }
            }
        }
    }
    auto it = std::find(local_clients.begin(), local_clients.end(),&client);
    if(it != local_clients.end())
    {
        if(client.getUsername() == "")
        {
            Logger::log(" Server + " + std::to_string(client.getUid()) + " left");
            removeServer(client.getUid());
        }
        else
        {
            Logger::log(client.getUsername() + " left");
        }
        local_clients.erase(it);
        user_list_changed = true;
    }
    close(socket_fd);
    Logger::log("leaving client handler ...");
}

int Server::decode_and_process(void *data, int sender_uid)
{
    LogInOut log;
    Message msg;
    flat_header header;
    int ret = 0;
    memcpy(&header.value, data, sizeof(Header));
    switch(header.header.type)
    {
    case LOGINOUT:
        log = Serialization::Serialize<LogInOut>::deserialize(data);
        ret = process_loginout(log, sender_uid);
        break;
    case MSG:
        msg = Serialization::Serialize<Message>::deserialize(data);
        ret = process_message(msg,data, header.header.length
                              + sizeof(Header)
                              + (2*STR_LEN), sender_uid);
        break;
    case CONTROLINFO:
        ret = process_controlInfo_request(data, sender_uid);

        break;
    }
    return ret;
}

void Server::connectToServers()
{
    addServer();
    for(NeighboorServer server : servers)
    {
        init_activ_socket(server.host, server.port);
        create_activ_socket();
    }
}

void Server::print_raw_data(char *data, int size) const
{
    Logger::log("Printing raw data");
    std::ofstream file;
    file.open("raw_data_server.log", std::ios::app);

    if(file.is_open())
    {
        if(data)
        {
            for(int i = 0; i < size; i++)
            {
                if(data[i] != 0)
                {
                    file << data[i];
                }
            }
            file << '\n';
        }
    }
    file.close();
}


int Server::process_loginout(LogInOut &log, int sender_uid)
{
    int ret;

    switch (log.header.flags) {
    case (SYN):
        ret = updateClient(std::string(log.username), sender_uid);
        break;
    case (SYN | FIN):
        ret = removeClient(getClient(sender_uid));
    default:
        break;
    }
    return ret;
}


void Server::send_error_message(const Message &message, int count, int sender_uid)
{
    std::string str = std::string("user ") + std::string(message.receiver)
            + " not found on this server";

    count = 0;
    Logger::log(str);
    error_message = create_message(name,
                                   std::string(message.sender),
                                   str.c_str(), str.size());
    void * reply = Serialization::Serialize<Message>::serialize(error_message);
    count = (2 * STR_LEN) + str.size() + sizeof(Header);
    sendToClient(sender_uid, reply, count);
}

int Server::process_message(const Message &message,
                            void *data, int len, int sender_uid)
{
    int count = 0;
    int sock = -1;
    std::string user = std::string(message.receiver);
    User *client = getClient(user);
    if(client)
    {
        sock = client->getSocket();
    }
    // the receiver is may be available from the the server
    else
    {
        // the receiver is not a local user. check if he is a remote
        // user.
        auto entry = remote_clients.find(user);
        if(entry == remote_clients.end())
        {
            send_error_message(message, count, sender_uid);
        }
        else
        {
            client = getClient(entry->second.getUid());
            if(client)
                sock = client->getSocket();
        }
    }
    if(sock != -1)
        count = write(sock, data, len);
    return count;
}

//TODO only send message to client with username
// Do not include server( client without name
int Server::process_get_request(int sender_uid)
{
    int ret = 0;
    auto users = getClientList();
    auto info = create_controlInfo2(users);
    int size = sizeof(Header) + 20 * users.size();
    void *data = Serialization::Serialize<ControlInfo>::serialize(info);
    ret = write(getClient(sender_uid)->getSocket(),
                data,
                size);
    Logger::log("Userlist sent to " +
                getClient(sender_uid)->getUsername());
    return ret;
}

int Server::process_controlInfo_request(void *data,int sender_uid)
{
    Header header;
    int ret = 0;
    if(data)
    {
        memcpy((char*)&header, data, 4);
        if(header.flags == GET) // a user made the request
        {
            ret = process_get_request(sender_uid);
        }
        else if(header.flags == 0) // a server has sent this userlist
        {
            ControlInfo info =
                    Serialization::Serialize<ControlInfo>::deserialize(data);
            update_userlist(info, sender_uid);
        }
    }
    return ret;
}

void Server::sendControlInfo()
{
    if(user_list_changed)
    {
        auto users = getClientList();
        auto info = create_controlInfo2(users);
        int size = sizeof(Header) + 20 * users.size();
        void *data = Serialization::Serialize<ControlInfo>::serialize(info);
        for(User *user : local_clients)
        {
            if(user->getUsername().empty())
            {
                write(user->getSocket(), data, size);
            }
        }
    }
    user_list_changed = false;
}

std::vector<RemoteEntry> Server::getClientList() const
{
    Logger::log(__PRETTY_FUNCTION__);
    std::vector<RemoteEntry> entries;
    RemoteEntry re;
    for(User *user : local_clients)
    {
        re.setUsername(user->getUsername());
        re.setHops(0);
        entries.push_back(re);
    }
    for(auto entry : remote_clients)
    {
        entries.push_back(entry.second);
    }
    return entries;
}

void Server::addServer()
{
    servers.push_back({"127.0.0.1", "50000"});
}

void Server::init_activ_socket(const std::string &server_ip, const std::string &server_port)
{
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        std::cerr << "signal" << std::endl;
    }
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_canonname = nullptr;
    hints.ai_addr = nullptr;
    hints.ai_next = nullptr;
    // Work with IPV4/6
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_protocol = 0;
    hints.ai_flags =  AI_NUMERICSERV ;
    // we could provide a host instead of nullptr
    if(getaddrinfo(server_ip.c_str(),
                   server_port.c_str(),
                   &hints,
                   &result) != 0)
    {
        perror("getaddrinfo()");
    }
}

void Server::create_activ_socket()
{
    addrinfo *rp;
    int socket_fd = -1;
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
            std::thread worker{&Server::client_handler,this, socket_fd};
            worker.detach();
            break; // success
        }
        close(socket_fd);
    }
}

void Server::print_userlist()
{
    auto users = getClientList();
    for(auto user : users)
    {
        Logger::log("User : " + user.getUsername());
    }
}

//int Server::sctp_init()
//{
//    int    listening_sock;
//    int    onoff = 1;
//    struct sockaddr_in  sin[1];
//    struct sctp_initmsg  initmsg;

//    // One to One Style
//    if ((listening_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1) {
//        perror("socket");
//        exit(1);
//    }

//    sin->sin_family = AF_INET;
//    sin->sin_port = htons(9012);
//    sin->sin_addr.s_addr = INADDR_ANY;
//    if (bind(listening_sock, (struct sockaddr *)sin, sizeof (*sin)) == -1) {
//        perror("bind");
//        exit(1);
//    }

//    if (listen(listening_sock, 1) == -1) {
//        perror("listen");
//        exit(1);
//    }

//    (void) memset(&initmsg, 0, sizeof(struct sctp_initmsg));
//    initmsg.sinit_num_ostreams = 1;
//    initmsg.sinit_max_instreams = 0;
//    initmsg.sinit_max_attempts = 1;
//    if (setsockopt(listening_sock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg,
//                   sizeof(struct sctp_initmsg)) < 0) {
//        perror("SCTP_INITMSG");
//        exit (1);
//    }

//    /* Events to be notified for */

//    return listening_sock;
//}


//int Server::sctp_accept(int listening_sock)
//{
//    // hack : header not available
//    Logger::log("Listen Success");
//    //int SOL_SCTP = 132;
//    struct sctp_paddrparams heartbeat;
//    struct sctp_event_subscribe events;
//    (void) memset(&events, 0, sizeof (events));
//    events.sctp_shutdown_event = 1;
//    heartbeat.spp_flags = SPP_HB_ENABLE;
//    heartbeat.spp_hbinterval = 5000;
//    heartbeat.spp_pathmaxrxt = 1;
//    /*Set Heartbeats*/
//        if(setsockopt(listening_sock, SOL_SCTP, SCTP_PEER_ADDR_PARAMS ,
//                      &heartbeat, sizeof(heartbeat)) != 0)
//            perror("setsockopt");
//        else
//            Logger::log("HB  Success");

//    if (setsockopt(listening_sock, IPPROTO_SCTP, SCTP_EVENTS, &events,
//                   sizeof (events)) < 0) {
//        perror("setsockopt SCTP_EVENTS");
//        exit(1);
//    }


//    /* Wait for new associations */
//    int flags;
//    for (;;) {

//        //Logger::log("New connexion ...");

//        /* Echo back any and all data */
//        mirror(0);
//    }
//}


        void Server::mirror(int sock)
{

}

int Server::updateClient(const std::string &username, int uid)
{
    Header header;
    header.length = 0;
    header.version = VERSION;
    header.type = LOGINOUT;
    header.flags = SYN | ACK;
    User *client = getClient(username);
    if(client)
    {
        header.flags |= DUP ;
    }
    else
    {
        user_list_changed = true;
        client = getClient(uid);
        client->setUsername(username);


    }
    int count = write(getClient(uid)->getSocket(), (void*)&header, 4);
    if(count > 0)
    {
        Logger::log(username + " logged in.");

    }

    if(header.flags == SYN | ACK)
    {
        //sendControlInfo();
    }

    client = nullptr;
    return count;
}
