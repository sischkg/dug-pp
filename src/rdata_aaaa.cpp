#include "rdata_aaaa.hpp"
#include <cstring>
#include <sstream>

namespace dns
{
    RecordAAAA::RecordAAAA( const uint8_t *addr )
    {
        std::memcpy( sin_addr, addr, sizeof( sin_addr ) );
    }

    std::string RecordAAAA::toString() const
    {
        std::stringstream buff;
        buff << std::hex << (uint32_t)sin_addr[ 0 ];
        for ( unsigned int i = 1; i < sizeof( sin_addr ); i++ ) {
            buff << ":" << (uint32_t)sin_addr[ i ];
        }
        return buff.str();
    }

    void RecordAAAA::outputWireFormat( WireFormat &message ) const
    {
        message.pushBuffer( reinterpret_cast<const uint8_t *>( &sin_addr ),
                            reinterpret_cast<const uint8_t *>( &sin_addr ) + sizeof( sin_addr ) );
    }

    RDataPtr RecordAAAA::parse( const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin != 16 )
            throw FormatError( "invalid AAAA Record length" );
        return RDataPtr( new RecordAAAA( begin ) );
    }
}
