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
#include <iostream>
using namespace std;

#include "netlink/socket.h"
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>


NL_NAMESPACE


#ifdef OS_WIN32

	static void close(int socketHandler) {
		closesocket(socketHandler);
	}


	static void freeaddrinfo(PADDRINFOA addrInfo) {
		::freeaddrinfo(addrInfo);
	}


	static const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
	{
			if (af == AF_INET)
			{
					struct sockaddr_in in;
					memset(&in, 0, sizeof(in));
					in.sin_family = AF_INET;
					memcpy(&in.sin_addr, src, sizeof(struct in_addr));
					getnameinfo((struct sockaddr *)&in, sizeof(struct
	sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
					return dst;
			}
			else if (af == AF_INET6)
			{
					struct sockaddr_in6 in;
					memset(&in, 0, sizeof(in));
					in.sin6_family = AF_INET6;
					memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
					getnameinfo((struct sockaddr *)&in, sizeof(struct
	sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
					return dst;
			}
			return NULL;
	}

#endif


static unsigned getInPort(struct sockaddr* sa) {

    if (sa->sa_family == AF_INET)
        return ntohs(((struct sockaddr_in*)sa)->sin_port);

    return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
}


static int getSocketErrorCode() {

    #ifdef OS_WIN32
        return WSAGetLastError();
    #else
        return errno;
    #endif
}


static unsigned getLocalPort(int socketHandler) {

    struct sockaddr_storage sin;

    #ifdef OS_WIN32
        int size;
    #else
        socklen_t size;
    #endif

    size = sizeof(sin);
    if(getsockname(socketHandler, (struct sockaddr*)&sin, &size) == 0)
        return getInPort((struct sockaddr*)&sin);
    else
        throw Exception(Exception::ERROR_GET_ADDR_INFO, "Socket::(static)getLocalPort: error getting socket info", getSocketErrorCode());
}


static void checkReadError(const string& functionName) {

    #ifdef OS_WIN32
        if(WSAGetLastError() != WSAEWOULDBLOCK)
            throw Exception(Exception::ERROR_READ, string("Socket::") + functionName + ": error detected", getSocketErrorCode());
    #else
        if(errno != EAGAIN && errno != EWOULDBLOCK)
            throw Exception(Exception::ERROR_READ, string("Socket::") + functionName + ": error detected", getSocketErrorCode());
    #endif
}


void Socket::initSocket(bool blocking, int nonBlockingConnextionTimeout) {

    struct addrinfo conf, *res = NULL;
    memset(&conf, 0, sizeof(conf));

    _inBufferUsed = 0;

    if(_type == SERVER || _protocol == UDP)
        conf.ai_flags = AI_PASSIVE;


    switch(_protocol) {

        case TCP:
            conf.ai_socktype = SOCK_STREAM;
            break;

        case UDP:
            conf.ai_socktype = SOCK_DGRAM;
            break;

        default:
            throw Exception(Exception::BAD_PROTOCOL, "Socket::initSocket: bad protocol");
    }

    switch(_ipVer) {

        case IP4:
            conf.ai_family = AF_INET;
            break;

        case IP6:
            conf.ai_family = AF_INET6;
            break;

        case ANY:
            conf.ai_family = AF_UNSPEC;
            break;

        default:
            throw Exception(Exception::BAD_IP_VER, "Socket::initSocket: bad ip version parameter");
    }

    char portStr[10];

    const char* host;

    if(_type == CLIENT && _protocol == TCP) {
        host = _hostTo.c_str();
        snprintf(portStr, 10, "%u", _portTo);
    }
    else {
        if(!_hostFrom.compare("") || !_hostFrom.compare("*"))
            host = NULL;
        else
            host = _hostFrom.c_str();

        snprintf(portStr, 10, "%u", _portFrom);
    }

    int status = getaddrinfo(host, portStr, &conf, &res);

    ReleaseManager<struct addrinfo> addrInfoReleaser(freeaddrinfo);
    addrInfoReleaser.add(&res);

    if(status != 0) {

        string errorMsg = "Socket::initSocket: Error setting addrInfo: ";

		#ifndef _MSC_VER
			errorMsg += gai_strerror(status);
		#endif
        throw Exception(Exception::ERROR_SET_ADDR_INFO, errorMsg, getSocketErrorCode());
    }

    while(!_connected && res) {

        _socketHandler = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

        if(_socketHandler != -1)

            switch(_type) {

                case CLIENT:
                    if(_protocol == UDP) {

                        if (bind(_socketHandler, res->ai_addr, res->ai_addrlen) == -1)
                            close(_socketHandler);
                        else
                        	_connected = true;
                    }
                    else {

                    	if(blocking){

                    		status = connect(_socketHandler, res->ai_addr, res->ai_addrlen);
                    	}
                    	else{

                    		setBlocking(false);

							status = connect(_socketHandler, res->ai_addr, res->ai_addrlen);
							if(status < 0 && errno == EINPROGRESS){
								fd_set myset;
								struct timeval tv;
								socklen_t lon;
								int valopt;
								int res;
								do{
									tv.tv_sec = nonBlockingConnextionTimeout;
									tv.tv_usec = 0;
									FD_ZERO(&myset);
									FD_SET(_socketHandler, &myset);
									res = select(_socketHandler+1, NULL, &myset, NULL, &tv);

									if(res < 0 && errno != EINTR){
										//Error connecting
										status = -1;
										break;
									}
									else if(res > 0){
										lon = sizeof(int);
										if(getsockopt(_socketHandler, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon)<0){
											//Error in getsockopt
											status = -1;
											break;
										}
										if(valopt){
											//Error in delayed connection
											status = -1;
											break;
										}
										//Connection OK
										status = 0;
										break;
									}
									else{
										//Timeout in select
										status = -1;
										break;
									}
								}while(1);
							}
                    	}
                        if(status != -1)
                        	_connected = true;
                        else
                           close(_socketHandler);
                    }

                    break;

                case SERVER:
                    #ifdef OS_WIN32
                        char yes = 1;
                    #else
                        int yes = 1;
                    #endif

                    if (setsockopt(_socketHandler, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
                        throw Exception(Exception::ERROR_SET_SOCK_OPT, "Socket::initSocket: Error establishing socket options");

                    if (bind(_socketHandler, res->ai_addr, res->ai_addrlen) == -1)
                        close(_socketHandler);
                    else
                    	_connected = true;

                    if (_protocol == TCP && listen(_socketHandler, _listenQueue) == -1)
                        throw Exception(Exception::ERROR_CAN_NOT_LISTEN, "Socket::initSocket: could not start listening", getSocketErrorCode());

                    break;

            }

    if(_connected && _ipVer == ANY)
        switch(res->ai_family) {
            case AF_INET:
                _ipVer = IP4;
                break;

            case AF_INET6:
                _ipVer = IP6;
                break;
        }

    res = res->ai_next;

    }

    if(!_connected)
        throw Exception(Exception::ERROR_CONNECT_SOCKET, "Socket::initSocket: error in socket connection/bind", getSocketErrorCode());


    if(!_portFrom)
        _portFrom = getLocalPort(_socketHandler);

    //freeaddrinfo(res);
}

/**
* CLIENT Socket constructor
*
* Creates a socket, connect it (if TCP) and sets it ready to send to hostTo:portTo.
* The local port of the socket is choosen by OS.
*
* @param hostTo the target/remote host
* @param portTo the target/remote port
* @param protocol the protocol to be used (TCP or UDP). TCP by default.
* @param ipVer the IP version to be used (IP4, IP6 or ANY). ANY by default.
* @throw Exception BAD_PROTOCOL, BAD_IP_VER, ERROR_SET_ADDR_INFO*, ERROR_CONNECT_SOCKET*,
*  ERROR_GET_ADDR_INFO*
*/
Socket::Socket(const string& hostTo, unsigned portTo, Protocol protocol, IPVer ipVer) :
                _hostTo(hostTo), _portTo(portTo), _portFrom(0), _protocol(protocol),
                _ipVer(ipVer), _type(CLIENT), _blocking(true), _listenQueue(0), _connected(false)
{
    initSocket();
}

/**
* CLIENT Socket constructor
*
* Creates a socket
* The local port of the socket is choosen by OS.
* @param protocol the protocol to be used (TCP or UDP)
* @param ipVer the IP version to be used (IP4, IP6 or ANY)
*/
Socket::Socket(Protocol protocol, IPVer ipVer, SocketType sockType) :
                _hostTo(""), _portTo(0), _portFrom(0), _protocol(protocol),
                _ipVer(ipVer), _type(sockType), _blocking(true), _listenQueue(0),
                _connected(false), _socketHandler(-1), _inBufferUsed(0)
{}



/**
* SERVER Socket constructor
*
* Creates a socket, binds it to portFrom port and listens for connections (if TCP).
*
* @param portFrom the local port the socket will be bound to
* @param protocol the protocol to be used (TCP or UDP). TCP by default.
* @param ipVer the IP version to be used (IP4, IP6 or ANY). IP4 by default.
* @param hostFrom the local address to be binded to (example: "localhost" or "127.0.0.1"). Empty (by default) or "*" means all avariable addresses.
* @param listenQueue the size of the internal buffer of the SERVER TCP socket where the connection requests are stored until accepted
* @throw Exception BAD_PROTOCOL, BAD_IP_VER, ERROR_SET_ADDR_INFO*, ERROR_SET_SOCK_OPT*,
*  ERROR_CAN_NOT_LISTEN*, ERROR_CONNECT_SOCKET*
*/
Socket::Socket(unsigned portFrom, Protocol protocol, IPVer ipVer, const string& hostFrom, unsigned listenQueue):
                _hostFrom(hostFrom), _portTo(0), _portFrom(portFrom), _protocol(protocol),
                _ipVer(ipVer), _type(SERVER), _blocking(true), _listenQueue(listenQueue), _connected(false)
{
    initSocket();
}

/**
* UDP CLIENT Socket Constructor
*
* This client constructor for UDP Sockets allows to expecify the local port the socket
* will be bound to. It sets the socket ready to send data to hostTo:portTo.
*
* @param hostTo the target/remote host
* @param portTo the target/remote port
* @param portFrom the local port the socket will be bound to
* @param ipVer the IP version to be used (IP4, IP6 or ANY). ANY by default.
* @throw Exception BAD_PROTOCOL, BAD_IP_VER, ERROR_SET_ADDR_INFO*, ERROR_SET_SOCK_OPT*,
*  ERROR_CAN_NOT_LISTEN*, ERROR_CONNECT_SOCKET*
*/
Socket::Socket(const string& hostTo, unsigned portTo, unsigned portFrom, IPVer ipVer):
                _hostTo(hostTo), _portTo(portTo), _portFrom(portFrom), _protocol(UDP),
                _ipVer(ipVer), _type(CLIENT), _blocking(true), _listenQueue(0), _connected(false)
{

    initSocket();
}


Socket::Socket() : _blocking(true), _socketHandler(-1) {};


/**
* Socket Destructor
*
* Closes (disconnects) the socket
*/

Socket::~Socket() {
    if(_socketHandler != -1)
        close(_socketHandler);
}


// get sockaddr, IPv4 or IPv6:
// This function is from Brian Beej Jorgensen Hall: Beej's Guide to Network Programming.
static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


/**
* Accepts a new incoming connection (SERVER Socket).
*
* Creates a new CLIENT socket to handle the communication (send/recieve data) of
* this accepted connection. Requires the socket to be a SERVER TCP socket. Throws an
* exception otherwise.
*
* @pre Socket must be SERVER
* @return A CLIENT socket that handles the new connection
* @throw Exception EXPECTED_TCP_SOCKET, EXPECTED_SERVER_SOCKET
*/
Socket* Socket::accept() {

    if(_protocol != TCP)
        throw Exception(Exception::EXPECTED_TCP_SOCKET, "Socket::accept: non-tcp socket can not accept connections");

    if(_type != SERVER)
        throw Exception(Exception::EXPECTED_SERVER_SOCKET, "Socket::accept: non-server socket can not accept connections");

    struct sockaddr_storage incoming_addr;

    #ifdef OS_WIN32
        int addrSize = sizeof(incoming_addr);
    #else
        unsigned addrSize = sizeof(incoming_addr);
    #endif

    int new_handler = ::accept(_socketHandler, (struct sockaddr *)&incoming_addr, &addrSize);

    if(new_handler == -1)
        return NULL;

    char hostChar[INET6_ADDRSTRLEN];
    inet_ntop(incoming_addr.ss_family, get_in_addr((struct sockaddr *)&incoming_addr), hostChar, sizeof hostChar);


    Socket* acceptSocket = new Socket();
    acceptSocket->_socketHandler = new_handler;
    acceptSocket->_hostTo = hostChar;
    acceptSocket->_portTo = getInPort((struct sockaddr *)&incoming_addr);
    acceptSocket->_portFrom = getLocalPort(acceptSocket->_socketHandler);

    acceptSocket->_protocol = _protocol;
    acceptSocket->_ipVer = _ipVer;
    acceptSocket->_type = CLIENT;
    acceptSocket->_listenQueue = 0;
    acceptSocket->setBlocking(_blocking);

    return acceptSocket;
}


/**
* Sends data to an expecific host:port
*
* Sends the data contained in buffer to a given host:port. Requires the socket to be an UDP socket,
* throws an exception otherwise.
*
* @pre Socket must be UDP
* @param buffer A pointer to the data we want to send
* @param size Size of the data to send (bytes)
* @param hostTo Target/remote host
* @param portTo Target/remote port
* @throw Exception EXPECTED_UDP_SOCKET, BAD_IP_VER, ERROR_SET_ADDR_INFO*, ERROR_SEND*
*/
void Socket::sendTo(const void* buffer, size_t size, const string& hostTo, unsigned portTo) {

    if(_protocol != UDP)
        throw Exception(Exception::EXPECTED_UDP_SOCKET, "Socket::sendTo: non-UDP socket can not 'sendTo'");

    struct addrinfo conf, *res;
    memset(&conf, 0, sizeof(conf));

    conf.ai_socktype = SOCK_DGRAM;

    switch(_ipVer) {

        case IP4:
            conf.ai_family = AF_INET;
            break;

        case IP6:
            conf.ai_family = AF_INET6;
            break;

        default:
            throw Exception(Exception::BAD_IP_VER, "Socket::sendTo: bad ip version.");
    }

    char portStr[10];
    snprintf(portStr, 10, "%u", portTo);

    int status = getaddrinfo(hostTo.c_str(), portStr, &conf, &res);

    ReleaseManager<struct addrinfo> addrInfoReleaser(freeaddrinfo);
    addrInfoReleaser.add(&res);


    if(status != 0) {
        string errorMsg = "Socket::sendTo: error setting addrInfo: ";
		#ifndef _MSC_VER
			errorMsg += gai_strerror(status);
		#endif
		throw Exception(Exception::ERROR_SET_ADDR_INFO, "Socket::sendTo: error setting addr info", getSocketErrorCode());
    }

    size_t sentBytes = 0;

    while(sentBytes < size) {

        int status = ::sendto(_socketHandler, (const char*)buffer + sentBytes, size - sentBytes, 0, res->ai_addr, res->ai_addrlen);

        if(status == -1)
            throw Exception(Exception::ERROR_SEND, "Socket::sendTo: could not send the data", getSocketErrorCode());

        sentBytes += status;
    }
}




/**
* Receive data and get the source host and port
*
* Requires the socket to be UDP. Source host address and port are returned in hostFrom and
* portFrom parameters. Data recieved is written in buffer address up to bufferSize.
*
* @pre Socket must be UDP
* @param buffer Pointer to a buffer where received data will be stored
* @param bufferSize Size of the buffer
* @param[out] hostFrom Here the function will store the address of the remote host
* @param[out] portFrom Here the function will store the remote port
* @return the length of the data recieved
* @throw Exception EXPECTED_UDP_SOCKET, ERROR_READ*
*/
int Socket::readFrom(void* buffer, size_t bufferSize, string* hostFrom, unsigned* portFrom) {

    if(_protocol != UDP)
        throw Exception(Exception::EXPECTED_UDP_SOCKET, "Socket::readFrom: non-UDP socket can not 'readFrom'");

    struct sockaddr_storage addr;
    socklen_t addrSize = sizeof(addr);
    int status = recvfrom(_socketHandler, (char*)buffer, bufferSize, 0, (struct sockaddr *)&addr, &addrSize);

    if(status == -1) {
        checkReadError("readFrom");
        if(hostFrom)
            *hostFrom = "";
        if(portFrom)
            *portFrom = 0;
    }

    else {

        if(portFrom)
            *portFrom = getInPort((struct sockaddr*)&addr);

        if(hostFrom) {
            char hostChar[INET6_ADDRSTRLEN];
            inet_ntop(addr.ss_family, get_in_addr((struct sockaddr *)&addr), hostChar, sizeof hostChar);

            *hostFrom = hostChar;
        }
    }

    return status;
}


/**
* Sends data
*
* Sends the data contained in buffer. Requires the Socket to be a CLIENT socket.
*
* @pre Socket must be CLIENT
* @param buffer A pointer to the data we want to send
* @param size Length of the data to be sent (bytes)
*/
int Socket::send(const void* buffer, size_t size) {
	int status;
	size_t sentData = 0;
	try{
			if(_type != CLIENT)
				return -1;
				//throw Exception(Exception::EXPECTED_CLIENT_SOCKET, "Socket::send: Expected client socket (socket with host and port target)");

			if(_protocol == UDP)
			{
				sendTo(buffer, size, _hostTo, _portTo);
				return (int) size;
			}

			while (sentData < size) {

				status = ::send(_socketHandler, (const char*)buffer + sentData, size - sentData, 0);

				if(status == -1)
				{
					_connected = false;
					return status;
					//throw Exception(Exception::ERROR_SEND, "Error sending data", getSocketErrorCode());
				}
				sentData += status;
			}
		}catch(Exception e){
	    	return -1;
	    }
    return sentData;
}

/**
* Receives data
*
* Receives data and stores it in buffer until bufferSize reached.
*
* @param buffer A pointer to a buffer where received data will be stored
* @param bufferSize Size of the buffer
* @return Size of received data or (-1) if Socket is non-blocking and there's no data received.
*/
int Socket::read(void* buffer, size_t bufferSize) {

    int status ;
    try{
    	status = recv(_socketHandler, (char*)buffer, bufferSize, 0);
		if(status == -1)
			checkReadError("read");
    }catch(Exception e){
    	return -1;
    }
    return status;
}

/**
* Get next read() data size
*
* Get the size of the data (bytes) a call to read() or readFrom() can process
*
* @return size of data the next call to read/readFrom will receive
*/
int Socket::nextReadSize() const {

	#ifdef OS_WIN32
		u_long result = -1;
	#else
		long int result = -1;
	#endif

    int status;

    try{
		#ifdef OS_WIN32
			status = ioctlsocket(_socketHandler, FIONREAD, &result);
		#else
			status = ioctl(_socketHandler, FIONREAD, &result);
		#endif
    }catch(Exception e){
    	return -1;
    }

    if(status)
    	return -1;
        //throw Exception(Exception::ERROR_IOCTL, "Socket::nextReadSize: error ioctl", getSocketErrorCode());

    return result;
}


/**
* Sets the blocking nature of the Socket
*
* Sets the Socket as blocking (if blocking is true) or as non-blocking (otherwise)
*
* @param blocking true to set the Socket as blocking; false to set the Socket as non-blocking
*/
void Socket::setBlocking(bool blocking) {

    _blocking = blocking;

    int result = -1;

    #ifdef OS_WIN32

        u_long non_blocking = !blocking;
        result = ioctlsocket(_socketHandler, FIONBIO, &non_blocking);
        if(result!=0)
            result = -1;
    #else

        int flags = fcntl(_socketHandler, F_GETFL);

        if(blocking)
            result = fcntl(_socketHandler, F_SETFL, flags & ~O_NONBLOCK);
        else
            result = fcntl(_socketHandler, F_SETFL, flags | O_NONBLOCK);
    #endif

    if (result == -1)
        throw Exception(Exception::ERROR_IOCTL, "Socket::blocking: ioctl error", getSocketErrorCode());
}

/**
* Connect the socket using address and port
* @param hostTo Target/remote host
* @param portTo Target/remote port
* @param blocking Blocking or not blocking mode
*/
void Socket::connectTo(const string& hostTo, unsigned portTo, bool blocking, int nonBlockingConnextionTimeout) {
	_hostTo = hostTo;
	_portTo = portTo;
	_connected = false;
	initSocket(blocking, nonBlockingConnextionTimeout);
}

/**
* Listen to socket using address and port
* @param hostFrom Target/remote host
* @param portFrom Target/remote port
* @param blocking Blocking or not blocking mode
*/
void Socket::listenTo(const string& hostFrom, unsigned portFrom, bool blocking, int nonBlockingConnextionTimeout) {
	_hostFrom = hostFrom;
	_portFrom = portFrom;
	_connected = false;
	initSocket(blocking, nonBlockingConnextionTimeout);
}

/**
* Listen to socket using port
* @param portFrom Target/remote port
* @param blocking Blocking or not blocking mode
*/
void Socket::listenTo(unsigned portFrom, bool blocking, int nonBlockingConnextionTimeout) {
	_hostFrom = "";
	_portFrom = portFrom;
	_connected = false;
	initSocket(blocking, nonBlockingConnextionTimeout);
}

/**
* Reconnect the socket
*/
void Socket::reconnect() {
	_connected = false;
	initSocket();
}



/**
* Closes (disconnects) the socket. After this call the socket can not be used.
*
* @warning Any use of the Socket after disconnection leads to undefined behaviour.
*/
void Socket::disconnect() {

    close(_socketHandler);
    _socketHandler = -1;
    _inBufferUsed = 0;
    _connected = false;

}

/**
* Returns whether the socket is connected
*
* @return socket connected status
*/
bool Socket::isConnected(){
    return _connected;
}

/**
* Read the socket and put what it contains in a local buffer
* /param timeout for reading udp socket in milliseconds
* @return number of bytes read
*/
int Socket::recvBuffer(int nonBlockingSelectTimeout)
{
	ssize_t rv = 0;
	size_t buffRemain = sizeof(_inBuffer) - _inBufferUsed;
	if(buffRemain == 0)
		return -1;

    if(_protocol == UDP) {
    	fd_set myset;
    	struct timeval tv;
    	int res = 0;
    	tv.tv_sec = (int)(nonBlockingSelectTimeout / 1000);
    	tv.tv_usec = (nonBlockingSelectTimeout % 1000) * 1000;
    	FD_ZERO(&myset);
    	FD_SET(_socketHandler, &myset);
    	res = select(_socketHandler+1, &myset, NULL, NULL, &tv);
    	if (res > 0) {
    		rv = recv(_socketHandler, (void*)&_inBuffer[_inBufferUsed], buffRemain, MSG_DONTWAIT);
    	}
    }
    else {
    	rv = recv(_socketHandler, (void*)&_inBuffer[_inBufferUsed], buffRemain, MSG_DONTWAIT);
    }

	if(rv == 0 || (rv < 0 && errno == EAGAIN))
		return 0;
	else if(rv < 0)
		return -2;

	_inBufferUsed += rv;

	return rv;
}

/**
* Read the local input buffer
*
* @param buf buffer to fill
*/
void Socket::getInBuffer(char *buf)
{
	memcpy(buf, _inBuffer, _inBufferUsed);
}

/**
* Read the local input buffer until the last separator character
*
* @param buf buffer to fill
* @param sep separator character
* @return number of bytes read, -1 if error
*/
int Socket::readBufferUntil(char *buf, int len, char sep)
{
	char *lineEnd;
	int ret;

	lineEnd = (char*) memchr((void*)_inBuffer, sep, _inBufferUsed);
	if(lineEnd == NULL){
		return 0;
	}else{
		lineEnd++;
		if((lineEnd - _inBuffer) <= len){
			memcpy(buf, _inBuffer, lineEnd - _inBuffer);
			ret = lineEnd - _inBuffer;
		}else{
			ret = -1; //Not enough space in the buffer
		}
	}

	// Shift buffer down so the unprocessed data is at the start
	_inBufferUsed -= (lineEnd -_inBuffer);
	memmove(_inBuffer, lineEnd, _inBufferUsed);

	return ret;
}

/**
* Read the local input buffer but don't move
* Should be used with moveBufferForward
*
* @param buf buffer to fill
* @param len buffer size
* @param offset _inBuffer offset to read from
* @return number of bytes read, -1 if error
*/
int Socket::readBufferAt(char *buf, unsigned int len, unsigned int offset)
{
	unsigned int lineEnd = len;
	if (buf != NULL && len > 0) {
		if (_inBufferUsed < len+offset) {
			lineEnd = _inBufferUsed;
		}
		memcpy(buf, _inBuffer+offset, lineEnd);
	}
	else {
		lineEnd = -1;
	}
	return lineEnd;
}

/**
* Move the local input buffer forward
*
* @param lineEnd bytes to move
* @return number of bytes moved, -1 if error
*/
int Socket::moveBufferForward(unsigned int lineEnd) {
	if (lineEnd <= _inBufferUsed) {
		_inBufferUsed -= lineEnd;
		memmove(_inBuffer, _inBuffer+lineEnd, _inBufferUsed);
		return lineEnd;
	}
	else {
		return -1;
	}
}

/**
* Get the TCP info of the socket
*
* @param tcpInfo tcp info struct to fill
* @return 0 if ok, -1 in case of error
*/
int Socket::getTcpInfo(tcp_info *tcpInfo)
{
	socklen_t tcp_info_length = sizeof(struct tcp_info);
	if (getsockopt(_socketHandler, SOL_TCP, TCP_INFO, (void *)tcpInfo, &tcp_info_length ) == 0 ) {
		return 0;
	}else{
		return -1;
	}
	/*
	printf("tcpi_last_data_sent: %u\ntcpi_last_data_recv:%u\ntcpi_snd_ssthresh:%u\ntcpi_rcv_ssthresh:%u\ntcpi_rtt:%u\ntcpi_rttvar:%u\ntcpi_lost:%u\ntcpi_retrans:%u\ntcpi_retransmits:%u\ntcpi_total_retrans:%u\ntcpi_unacked:%u\ntcpi_state:%u",
		tcpInfo.tcpi_last_data_sent,
		tcpInfo.tcpi_last_data_recv,
		tcpInfo.tcpi_snd_ssthresh,
		tcpInfo.tcpi_rcv_ssthresh,
		tcpInfo.tcpi_rtt,
		tcpInfo.tcpi_rttvar,
		tcpInfo.tcpi_lost,
		tcpInfo.tcpi_retrans,
		tcpInfo.tcpi_retransmits,
		tcpInfo.tcpi_total_retrans,
		tcpInfo.tcpi_unacked,
		tcpInfo.tcpi_state
	);
	*/
}

/**
* Get the TCP info lost byte
*
* @return tcpi_lost if ok, -1 in case of error
*/
int Socket::getTcpPckLost()
{
	tcp_info tcpInfo;
	socklen_t tcp_info_length = sizeof(tcp_info);
	if (getsockopt(_socketHandler, SOL_TCP, TCP_INFO, (void *)&tcpInfo, &tcp_info_length ) == 0 ) {
		return tcpInfo.tcpi_lost;
	}else{
		return -1;
	}
}

/**
 * Get the TCP info retrans byte
 *
 * @return tcpi_lost if ok, -1 in case of error
 */
 int Socket::getTcpPckRetrans()
 {
 	tcp_info tcpInfo;
 	socklen_t tcp_info_length = sizeof(tcp_info);
 	if (getsockopt(_socketHandler, SOL_TCP, TCP_INFO, (void *)&tcpInfo, &tcp_info_length ) == 0 ) {
 		return tcpInfo.tcpi_retrans;
 	}else{
 		return -1;
 	}
 }

/**
* @include socket.inline.h
*/


NL_NAMESPACE_END
