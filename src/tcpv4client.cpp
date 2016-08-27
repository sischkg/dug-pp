#include "tcpv4client.hpp"
#include "utils.hpp"
#include <arpa/inet.h>
#include <boost/scoped_array.hpp>
#include <boost/lexical_cast.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

namespace tcpv4
{
    const uint16_t TCP_RECEIVE_BUFFER_SIZE = 65535;

    Client::~Client()
    {
        closeSocket();
    }

    void Client::openSocket()
    {
        if ( tcp_socket > 0 ) {
            closeSocket();
        }

        tcp_socket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
        if ( tcp_socket < 0 ) {
            std::string msg = get_error_message( "cannot create socket", errno );
            throw SocketError( msg );
        }
        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convertAddressStringToBinary( parameters.address );
        socket_address.sin_port   = htons( parameters.port );
	int result = connect( tcp_socket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof( socket_address ) );
        if ( result < 0 ) {
            closeSocket();
            std::string msg = "cannot connect to " + parameters.address + ":" + boost::lexical_cast<std::string>( parameters.port );
            throw SocketError( get_error_message( msg, errno ) );
        }
    }

    void Client::closeSocket()
    {
        if ( tcp_socket > 0 ) {
            close( tcp_socket );
            tcp_socket = -1;
        }
    }

    void Client::shutdown( int how )
    {
        if ( tcp_socket > 0 ) {
            ::shutdown( tcp_socket, how );
        }
    }

    void Client::shutdownRead()
    {
	if ( tcp_socket > 0 ) {
	    shutdown( SHUT_RD );
	}
    }

    void Client::shutdownWrite()
    {
	if ( tcp_socket > 0 ) {
	    shutdown( SHUT_WR );
	}
    }

    uint16_t Client::send( const uint8_t *data, uint16_t size )
    {
        if ( tcp_socket < 0 )
            openSocket();

        int sent_size = write( tcp_socket, data, size );
        if ( sent_size < 0 ) {
            std::string msg = "cannot send to " + parameters.address + ":" + boost::lexical_cast<std::string>( parameters.port );
            throw SocketError( get_error_message( msg, errno ) );
        }
        return sent_size;
    }

    uint16_t Client::send( const WireFormat &data )
    {
        if ( tcp_socket < 0 )
            openSocket();

        return data.send( tcp_socket, NULL, 0, 0 );
    }

    const int RECEIVE_BUFFER_SIZE = 0xffff;

    uint16_t Client::receive( PacketData &buffer, bool is_nonblocking )
    {
        if ( tcp_socket < 0 )
            openSocket();

        int flags = 0;
        if ( is_nonblocking )
            flags |= MSG_DONTWAIT;

        buffer.resize( TCP_RECEIVE_BUFFER_SIZE );
        ssize_t recv_size = read( tcp_socket, buffer.data(), buffer.size() );

        if ( recv_size < 0 ) {
            throw SocketError( get_error_message( "cannot recv packet",  errno ) );
        }
        buffer.resize( recv_size );

        return recv_size;
    }

    bool Client::isReadable()
    {
        return true;
    }
}
