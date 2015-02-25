/*
    NetLink Sockets: Networking C++ library
    Copyright 2012 Pedro Francisco Pareja Ruiz (PedroPareja@Gmail.com)

    This file is part of NetLink Sockets.

    NetLink Sockets is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetLink Sockets is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetLink Sockets. If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef __NL_SOCKET
#define __NL_SOCKET

#include "netlink/core.h"

#define BUFFER_SIZE 4096

typedef struct tcp_info tcp_info;

NL_NAMESPACE

/**
* @class Socket socket.h netlink/socket.h
*
* Socket class
*
* @note The Exceptions with asterisk(*) includes the native error code (Exception::nativeErrorCode()) when thrown
* @warning Remember to call init() before using Socket
*/

class Socket {

    private:
        string      _hostTo;
        string      _hostFrom;
        unsigned    _portTo;
        unsigned    _portFrom;
        Protocol    _protocol;
        IPVer       _ipVer;
        SocketType  _type;
        bool        _blocking;
        unsigned    _listenQueue;
        bool      	_connected;
        int         _socketHandler;
        char        _inBuffer[BUFFER_SIZE];
        size_t      _inBufferUsed;


    public:

        Socket(Protocol protocol, IPVer ipVer, SocketType sockType = CLIENT);

        Socket(const string& hostTo, unsigned portTo, Protocol protocol = TCP, IPVer ipVer = ANY);

        Socket(unsigned portFrom, Protocol protocol = TCP, IPVer ipVer = IP4, const string& hostFrom = "", unsigned listenQueue = DEFAULT_LISTEN_QUEUE);

        Socket(const string& hostTo, unsigned portTo, unsigned portFrom, IPVer ipVer = ANY);

        ~Socket();


        Socket* accept();

        int read(void* buffer, size_t bufferSize);
        int send(const void* buffer, size_t size);

        int readFrom(void* buffer, size_t bufferSize, string* HostFrom, unsigned* portFrom = NULL);
        void sendTo(const void* buffer, size_t size, const string& hostTo, unsigned portTo);

        int nextReadSize() const;

        void disconnect();

        void reconnect();
        void connectTo(const string& hostTo, unsigned portTo, bool blocking = true, int nonBlockingConnextionTimeout = 10);
        void listenTo(const string& hostFrom, unsigned portFrom, bool blocking = true, int nonBlockingConnextionTimeout = 10);
        void listenTo(unsigned portFrom, bool blocking = true, int nonBlockingConnextionTimeout = 10);

        const string&   hostTo() const;
        const string&   hostFrom() const;
        unsigned        portTo() const;
        unsigned        portFrom() const;
        Protocol        protocol() const;
        IPVer           ipVer() const;
        SocketType      type() const;
        unsigned        listenQueue() const;
        int             socketHandler() const;
        bool            isBlocking() const;

        void 			setBlocking(bool blocking);
        bool            isConnected() ;
        void 			getInBuffer(char *buf);
        int 			moveBufferForward(unsigned int lineEnd);
        int 			recvBuffer(int nonBlockingSelectTimeout = 200);
        int 			readBufferUntil(char *buf, int len, char sep);
        int				readBufferAt(char *buf, unsigned int len, unsigned int offset);
        int 			getTcpInfo(tcp_info *tcpInfo);
        int 			getTcpPckLost();
        int 			getTcpPckRetrans();


    private:

        void initSocket(bool blocking = true, int nonBlockingConnextionTimeout = 10);
        Socket();

};

#include <netlink/socket.inline.h>

NL_NAMESPACE_END

#endif
