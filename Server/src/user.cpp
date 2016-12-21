#include "../include/user.h"

int User::client_uid = 0;
User::User(int fd)
{
    uid = ++client_uid;
    setSocket(fd);
    connected = false;
    gone = false;
    username = "";
}
void User::setSocket(int fd)
{
    this->fd = fd;
}

int User::getSocket()const
{
    return fd;
}

int User::getUid()const
{
    return uid;
}

std::string User::getUsername()const
{
    return username;
}

void User::setUsername(const std::string &username)
{
    this->username = username;
}

bool User::isConnected()const
{
    return connected;
}

void User::setConnected(bool flag)
{
    connected = flag;
}

bool User::isGone()const
{
    return gone;
}

void User::setGone()
{
    gone = true;
}
