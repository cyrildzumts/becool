#ifndef SERVER_H
#define SERVER_H
#include "common.h"
#include "user.h"
#include "serialization.h"
#include "logger.h"
#include <iterator>
#include <algorithm>


using ms = std::chrono::milliseconds;
class Server
{
public:
    Server();
    /**
     * @brief init
     */

    void init();
    /**
     * @brief start
     */
    void start();

    int create_socket();
    void hearbeat();

    /**
     * @brief removeClient
     * @param client
     */
    int removeClient(User* client);

    /**
     * @brief getServer
     * @param pos
     * @return
     */
    NeighboorServer *getServer(size_t pos);
    /**
     * @brief removeServer
     * @param pos
     */
    void removeServer(size_t pos);


    /**
     * @brief client_handler
     * @param socket_fd
     */
    void client_handler(int socket_fd);

    /**
     * @brief sendToClient
     * @param client_uid
     * @param data
     * @param n
     */
    int sendToClient(int client_uid, void *data, int n);


    /**
     * @brief updateControlInfo
     */
    int updateControlInfo();

    /**
     * @brief decode_and_process
     * @param data
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
    int process_get_request(int sender_uid);
    int process_controlInfo_request(void *data, int sender_uid);
    NeighboorServer* getNextServer()const;

private:
    int listening_socket;
    //std::mutex client_shield;
    std::timed_mutex client_shield;
    std::mutex server_shield;
    std::vector<User*> clients;
    std::vector<NeighboorServer*> servers;

    sockaddr *addr;
    socklen_t addrlen;
    addrinfo hints;
    addrinfo *result;
    int flags;
    std::string port;
    bool stopped;
    Message error_message;
    std::string name;
    void send_error_message(const Message &message, int count);
};

#endif // SERVER_H
