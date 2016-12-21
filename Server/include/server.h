#ifndef SERVER_H
#define SERVER_H
#include "common.h"
#include "user.h"
#include "remoteentry.h"
#include "serialization.h"
#include "logger.h"
#include <iterator>
#include <algorithm>


using ms = std::chrono::milliseconds;
class Server
{
public:
    Server(const std::string &ip, const std::string &port);
    Server();
    /**
     * @brief init initialize the socket this server will use.
     */

    void init();
    /**
     * @brief start this method simply start this server.
     * init() must be already called before calling start().
     */
    void start();

    /**
     * @brief create_socket a listening socket
     * @return on success returns the created socket
     *         on error return SOCKET_ERROR , which is -1
     */
    int create_socket();
    void hearbeat();

    /**
     * @brief removeClient removes client from the list of
     * connected clients.
     * @param client the client to be removed
     */
    int removeClient(User* client);

    /**
     * @brief getServer query a neighbor Server
     * @param pos the position of the desired server
     * @return a pointer to the desired server on success
     *         nullptr is return when pos is invalid
     */
    NeighboorServer *getServer(size_t pos);
    /**
     * @brief removeServer
     * @param pos
     */
    void removeServer(int server_uid);


    /**
     * @brief client_handler this the task run by the thread servicing
     * the connection associated to a socket
     * @param socket_fd the socket descriptor of this connection
     */
    void client_handler(int socket_fd);

    /**
     * @brief sendToClient sends n byte from data to the client attached
     * to client_uid. This method is primarly used to transfer message between
     * connected users.
     * @param client_uid the uid of the client the message is destinated
     * @param data the message to transfer.
     * @param n the number of byte from data we want to send.
     */
    int sendToClient(int client_uid, void *data, int n);


    /**
     * @brief updateControlInfo
     */
    int updateControlInfo();

    /**
     * @brief decode_and_process utility method used to decode every
     * received data and call an appropiatre hanlder to process the data.
     * @param data the received to be processed
     * @param sender_uid the uid of the sender.
     */
    int decode_and_process(void *data, int sender_uid);

private:
    void print_raw_data(char *data, int size)const;
    /**
     * @brief addClient
     * @param client
     */
    void addClient(User *client);
    /**
     * @brief updateClient
     * @param username
     * @param uid
     * @return
     */
    int updateClient(const std::string &username, int uid);
    /**
     * @brief getClient
     * @param username
     * @return
     */
    User* getClient(const std::string &username);
    /**
     * @brief getClient
     * @param fd
     * @return
     */
    User* getClient(int uid);

    /**
     * @brief update_userlist update the userlist
     * @param info contains the userlist
     * @param sender_uid the uid of the server who sent me this list
     */
    void update_userlist(const ControlInfo &info, int sender_uid);
    void update_local_list();
    int process_loginout(LogInOut& log, int sender_uid);
    int process_message(const Message &message,
                        void *data,int len);

    //TODO only send message to client with username
    // Do not include server( client without name
    int process_get_request(int sender_uid);
    int process_controlInfo_request(void *data, int sender_uid);
    void sendControlInfo();
    std::vector<RemoteEntry> getClientList()const;
    NeighboorServer* getNextServer()const;

private:
    int listening_socket;
    //std::mutex client_shield;
    std::timed_mutex client_shield;
    std::mutex server_shield;
    std::vector<User*> local_clients;
    std::vector<NeighboorServer*> servers;
    /**
     * @brief remote_users users available through another server
     * for look up this map structure is used :
     * <username , socketfd>
     */

    std::map<std::string, RemoteEntry> remote_clients;

    sockaddr *addr;
    socklen_t addrlen;
    addrinfo hints;
    addrinfo *result;
    int flags;
    std::string port;
    bool stopped;
    Message error_message;
    std::string name;
    std::string ip;
    bool user_list_changed;
    void send_error_message(const Message &message, int count);
};

#endif // SERVER_H
