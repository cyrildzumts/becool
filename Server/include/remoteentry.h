#ifndef REMOTEENTRY_H
#define REMOTEENTRY_H

#include <string>
#include <vector>
#include "protocol.h"

class RemoteEntry
{
public:
    RemoteEntry();
    int getUid()const;
    void setUid(int uid);
    std::string getUsername()const;
    void setUsername(const std::string &username);
    int getHops()const;
    void setHops(int hops);
private:
    int uid;
    int hops;
    std::string username;

};

ControlInfo create_controlInfo2(const std::vector<RemoteEntry> &users);
#endif // REMOTEENTRY_H
