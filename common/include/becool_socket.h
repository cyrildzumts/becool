#ifndef BECOOL_SOCKET_H
#define BECOOL_SOCKET_H
/*************************************************************
 * Socket Interface
 * Author : Cyrille Ngassam Nkwenga
 * 2017
 * Computer Network Programming
 ************************************************************/


#include "common.h"
#include "logger.h"
class Socket
{
public:
    virtual ~Socket(){}

    virtual int getSocket()const;

    /**
     * @brief sock_init initialize the socket
     * to the socket
     */
    virtual void sock_init() = 0;
    /**
     * @brief sock_create create the appropiatre
     * socket. This method should be called only
     * after sock_init().
     * @return  -a socket descriptor on success
     *          - -1 on error
     */
    virtual int sock_create() ;
    /**
     * @brief sock_bind bind the socket create by
     * sock_create() to the desired ip address
     * @return  0 on success
     *          -1 on error
     */
    virtual int sock_bind();
    /**
     * @brief sock_listen marks the socket created by
     * sock_create() as passiv socket.
     * @return  0 on success
     *          -1 on error
     */
    virtual int sock_listen();
    /**
     * @brief sock_connect connects the socket to the
     * server ip address
     * @return 0 on success
     *         -1 on error
     */
    virtual int sock_connect();
    /**
     * @brief sock_accept accepts connexion to the listening
     * socket. This is a blocking function
     * @return 0 on success
     *         -1 on error
     */
    virtual int sock_accept();
    /**
     * @brief sock_close closes the socket created  by
     * sock_create().
     */
    virtual void sock_close();
    /**
     * @brief sock_send sends "count" byte from buffer to
     * to_fd.
     * @param to_fd the destination where to send bytes
     * @param buffer The memory region containing the data
     * to send
     * @param count the number of bytes to be sent
     * @return the number of sent byte on success.
     *         on error  return -1
     */
    virtual int sock_send(int to_fd, char *buffer, size_t count);
    /**
     * @brief sock_read read count byte from from_fd and save the bytes in
     * buffer
     * @param from_fd the sender of the data
     * @param buffer where to save the received data
     * @param count maximum number of bytes to read.
     * @return on success returns the number of bytes read.
     *         on error returns -1
     */
    virtual int sock_read(int from_fd, char *buffer, size_t count);

protected:
    int socket_fd;
    sockaddr *addr;
    socklen_t addrlen;
    addrinfo hints;
    addrinfo *result;
    int flags;
    std::string port;
    bool stopped;
    std::string name;
    std::string ip;
};


class TCPSocket : public Socket
{

public:
    TCPSocket(const std::string &ip, const std::string &port);
    ~TCPSocket();
    // Socket interface
public:
    virtual void sock_init() override;
    virtual int sock_accept() override;
};

class SCTPSocket : public Socket
{


    // Socket interface
public:
    virtual void sock_init() override;
    virtual int sock_create() override;
    virtual int sock_accept() override;
    virtual int sock_send(int to_fd, char *buffer, size_t count) override;
    virtual int sock_read(int from_fd, char *buffer, size_t count) override;

private:
    sockaddr_in sockaddr;
    sctp_paddrparams heartbeat;
    sctp_initmsg initmsg;
    sctp_event_subscribe events;
    sctp_sndrcvinfo sndrcvinfo;

};

#endif // BECOOL_SOCKET_H
