#include "remoteentry.h"

RemoteEntry::RemoteEntry()
{
    hops = -1;
    uid = -1;
}

int RemoteEntry::getUid() const
{
    return uid;
}

void RemoteEntry::setUid(int uid)
{
    this->uid = uid;
}

std::string RemoteEntry::getUsername() const
{
    return username;
}

void RemoteEntry::setUsername(const std::string &username)
{
    this->username = username;
}

int RemoteEntry::getHops() const
{
    return hops;
}

void RemoteEntry::setHops(int hops)
{
    this->hops = hops;
}


ControlInfo create_controlInfo2(const std::vector<RemoteEntry> &users)
{
    ControlInfo info;
    info.header.type = CONTROLINFO;
    info.header.version = VERSION;

    info.entries = new Entry[users.size()];
    info.header.flags = 0;
    for(int i = 0; i < users.size(); i++)
    {
        memset(info.entries[i].username,
               0,
               STR_LEN);

        info.entries[i].hops = users.at(i).getHops();
        memcpy(info.entries[i].username,
               users.at(i).getUsername().c_str(),
               users.at(i).getUsername().size());
    }
    info.header.length = users.size();
    return info;
}
