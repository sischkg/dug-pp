#ifndef TCPV4CLIENT_HPP
#define TCPV4CLIENT_HPP

#include "utils.hpp"
#include "wireformat.hpp"
#include <boost/cstdint.hpp>
#include <string>
#include <vector>

namespace tcpv4
{
    class Client
    {
    private:
        ClientParameters parameters;
        int              tcp_socket;
        void             shutdown( int );

    public:
        Client( const ClientParameters &param )
	    : parameters( param ), tcp_socket( -1 )
        {}
        ~Client();

        void openSocket();
        void closeSocket();
        void shutdownRead();
        void shutdownWrite();

        uint16_t send( const uint8_t *data, uint16_t size );
        uint16_t send( const uint8_t *begin, const uint8_t *end )
        {
            return send( begin, end - begin );
        }
        uint16_t send( const PacketData &packet )
        {
            return send( packet.data(), packet.size() );
        }
        uint16_t send( const WireFormat & );

        uint16_t receive( PacketData &data, bool is_nonblocking = false );
        bool isReadable();
    };
}

#endif
