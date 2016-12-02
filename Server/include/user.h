#ifndef CLIENT_H
#define CLIENT_H

#include <string>

class User
{
public:
    explicit User(int fd);
    int getUid()const;
    bool isConnected()const;
    void setConnected(bool flag);
    int getSocket()const;
    std::string getUsername()const;
    void setUsername(const std::string &username);
    bool isGone()const;
    void setGone();


private:
    void setSocket(int fd);
private:
    static int client_uid;
    int fd;
    bool connected;
    bool gone;
    int uid;
    std::string username;
};

#endif // CLIENT_H
