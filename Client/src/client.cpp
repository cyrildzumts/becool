#include "../include/client.h"

Client *Handler::client = nullptr;

Client::Client() :Client(SERVER_IP, SERVER_PORT)
{

}

Client::Client(const std::string &server_ip, const std::string &port):ip{server_ip}, port{port}
{

    quit =false;
    loggedIn =false;
    stop_reading = false;
    stop_writting = false;
    //sock_client = new TCPSocket(server_ip, port);
    sock_client = new SCTPSocket(server_ip, port);

    usage =std::string
                (
                     "-------------------------------------------------------------\n"
                     " Usage : \n"
                     "-- To send a message, please type in :"
                     " /username + message \n"
                     "-- and validate your action with the Enter key.\n"
                     "-- To logout  please enter /logout and validate with \n"
                     "-- with Enter key. This will quit the application as well.\n"
                     "-- To see the list of available users to chat with, please \n"
                     "-- enter /users and validate with the Enter key\n"
                     "-- To quit this application, please enter /quit and then\n"
                     "-- validate with the Enter key\n"
                     "-------------------------------------------------------------\n"
                );

    head =           "-------------------------------------------------------------\n"
                     "--                 Welcome to Becool \n"
                     "--                 Copyright 2016\n"
                     "-------------------------------------------------------------\n";
}

Client::~Client()
{

}


void Client::irq_handler(int irq)
{
    if(irq == SIGINT)
    {
        Logger::log("\n... quitting the app ");
        //logout();
        quit = true;
    }
}

void Client::init()
{
    sock_client->sock_init(false);
}

int Client::create_socket()
{
    return sock_client->sock_connect();
}
void Client::logout()
{

    LogInOut log = create_loginout(username, false);
    void *data = Serialization::Serialize<LogInOut>::serialize(log);
    int size = STR_LEN + sizeof(Header);
    send_data(data, size);
    while (!txd_data.empty()) {

    }
    quit = true;
    stop_writting = true;
    stop_reading = true;
}

int Client::login()
{

    bool username_invalid = true;
    std::string username;
    Logger::log(head);
    Logger::log(usage);
    Logger::log("Please enter a login to register to the server");

    int ret = 0;
    LogInOut log;
    while(username_invalid && !loggedIn)
    {
        Logger::log( "username : ");
        std::cout << std::flush;
        std::getline(std::cin, username, '\n');
        if(username.size() > STR_LEN)
        {
            Logger::log("\n username too long ");

        }
        else if(username.size() < 3)
        {
            Logger::log("\n username too short ");

        }
        else
        {
            log = create_loginout(username);
            void *data = Serialization::Serialize<LogInOut>::serialize(log);
            int len = STR_LEN + sizeof(Header);
            sock_client->sock_send((char*)data, len);
            ret = sock_client->sock_read((char*)data, sizeof(Header));
            if(ret <= 0)
            {
                Logger::log("Connexion error with server: unable to read from socket");
                exit(EXIT_FAILURE);
            }

            if(ret > 1)
            {
                decode(data, ret);
            }
            if(ret == 1)
            {
                ret = sock_client->sock_read((char*)data, len);
                if(ret > 1)
                {
                    decode(data, ret);
                }
            }

            if(loggedIn)
            {
                Logger::log("User logged in");
                this->username = username;
                break;
            }
        }

    }
    return ret;
}

void Client::start()
{
   create_socket();
   std::thread w_worker{&Client::write_task, this};
   w_worker.detach();
   login();
   shell();
}

void Client::send_data(void *data, int size)
{
    if((data != nullptr) && (size > 0))
    {
        print_raw_data((char*)data, size);
        std::pair<void*, int> entry;
        entry.first = data;
        entry.second = size;
        txd_data.push(entry);
    }

}

int Client::decode(void *data, int size)
{
    int ret = -1;
    char *ptr = (char*)data;
    LogInOut log;
    Message msg;
    Header header;
    memcpy(&header, ptr, sizeof(Header));
    switch(header.type)
    {
      case LOGINOUT:
        log = Serialization::Serialize<LogInOut>::deserialize(data);
        ret = process_loginout(log);
        break;
     case MSG:
        msg = Serialization::Serialize<Message>::deserialize(data);
        ret = process_message(msg);
        break;
    case CONTROLINFO:
        ret = process_get_request(data);
    }
    ptr = nullptr;
    memset(data, 0, size);
    return ret;
}

void Client::print_raw_data(char *data, int size) const
{
    std::ofstream file;
    file.open("raw_data_client.log", std::ios::app);

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
void Client::shell()
{
    std::thread r_worker{&Client::read_task, this};

    r_worker.detach();
    ControlInfo info;
    LogInOut loginout;
    std::string receiver;
    std::string line;
    Message msg;
    char *ptr = nullptr;
    int size = 0;

    std::cin.tie(&std::cout);
    while(!quit)
    {

        Logger::log(username + " : " );
        std::cout << std::flush;
        std::getline(std::cin,line, '\n');
        if( (line == "/quit") || (line == "/logout") )
        {
            logout();
            ptr = nullptr;
            break;
        }
        else if(line == "/GET" || line == "/info" || line == "/users")
        {
            info = create_controlInfo(
                        std::vector<std::string>());

            ptr = (char*)Serialization::Serialize<ControlInfo>::serialize(
                        info);
            size = sizeof(Header)
                    + (info.header.length * sizeof(Entry));
        }
        else if((line == "/help") ||  (line == "--h"))
        {
            Logger::log(usage);
        }
        else
        {
            std::vector<std::string> args = Tools::input_arg_reader(line);
            if(!args.empty())
            {
                receiver = args.at(0);
                line = args.at(1);
                msg = create_message(username,receiver,
                                     line.c_str(), line.size());
                ptr = (char*)Serialization::Serialize<Message>::serialize(msg);
                size = (2 * STR_LEN) + line.size() + sizeof(Header);
            }
            else
            {
                ptr = nullptr;
                Logger::log("Bad input formating. please see the usage text"
                            " by entering /help");
            }
        }
        if(ptr && size)
            send_data(ptr, size);
        size = 0;

    }
    Logger::log("Quitting the shell ...");
}

int Client::process_loginout(const LogInOut &log)
{

    int ret = -1;
    if(log.header.flags == (SYN | ACK | DUP))
    {
        Logger::log("username already in use");
    }
    else if(log.header.flags == (SYN | ACK ))
    {
        loggedIn = true;
        ret = 0;
        Logger::log("you successfuly logged in");
    }
    else if(log.header.flags == (FIN | ACK))
    {
        Logger::log("you successfuly logged out");
        quit = true;
        loggedIn = false;
        ret = 0;
    }

    return ret;
}


int Client::process_message(const Message &msg)
{
    std::string str = std::string(msg.sender)
            + " : "
            + std::string(msg.data);
    Logger::log(str);
    return 0;
}

int Client::process_get_request(void *data)
{
    ControlInfo info = Serialization::Serialize<ControlInfo>::deserialize(data);
    std::string user;
    userlist.clear();
    for(int i = 0; i < info.header.length; i++)
    {
        user = info.entries[i].username;
        userlist.push_back(user);
    }
    show_userlist();
    return 0;
}

void Client::send_test()
{
    Logger::log("Starting send test ...");
    std::string receiver = "Jacob";
    std::thread r_worker{&Client::read_task, this};

    r_worker.detach();
    std::vector<std::string> strings;
    int size;
    for(int i = 0; i < 10; i++)
    {
        strings.push_back(std::string("Test " + std::to_string(i)));
    }
    void *data = nullptr;
    Message msg;
    for(std::string str : strings)
    {
        msg = create_message(username, receiver, str.c_str(), str.size());

        data = Serialization::Serialize<Message>::serialize(msg);
        size = sizeof(Header) + (2*STR_LEN) + str.size();
        send_data(data, size);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    }
    strings.clear();
    close(socket_fd);
    Logger::log("send test terminated ...");
}

void Client::show_userlist() const
{
    Logger::log("Available Users : "
                + std::to_string(userlist.size())
                );
    for(std::string user : userlist)
    {
        Logger::log("* " + user);
    }
}

void Client::read_task()
{
    int count = 0;
    char buffer[BUFFER_SIZE] = {0};
    char *ptr = nullptr;
    while(!(quit && stop_reading) )
    {
        count = sock_client->sock_read(buffer, BUFFER_SIZE );
        if(count <= 0)
        {
            perror("Read Task: ");
            quit = true;
            stop_reading = true;
            exit(EXIT_FAILURE);
            break;
        }
        else if(count == 1)
        {
            //Logger::log("heartbeat signal received ...");
        }
        else if(count > 1)
        {
            ptr = new char[count];
            memcpy(ptr, buffer, count);
            decode(ptr, count);
            delete[] ptr;
        }
    }
    Logger::log("Read Task exit ...");
}

void Client::write_task()
{
    std::pair<void*, int> entry;

    while(!(quit && stop_writting))
    {
        txd_data.wait_and_pop(entry);
        if(sock_client->sock_send((char*)entry.first, entry.second) < 0)
        {
            perror("Write Task: ");
            quit = true;
            stop_writting = true;
            break;
        }
        //else Logger::log("Client : data sent ...");
    }
}
