#include "rdata_a.hpp"
#include <cstring>

namespace dns
{
    RecordA::RecordA( uint32_t addr ) : sin_addr( addr )
    {
    }

    RecordA::RecordA( const std::string &addr )
    {
        in_addr a = convert_address_string_to_binary( addr );
        std::memcpy( &sin_addr, &a, sizeof( sin_addr ) );
    }

    std::string RecordA::toString() const
    {
        char buf[ 256 ];
        std::snprintf( buf,
                       sizeof( buf ),
                       "%d.%d.%d.%d",
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 1 ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 2 ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 3 ) );
        return std::string( buf );
    }

    void RecordA::outputWireFormat( WireFormat &message ) const
    {
        message.push_back( ( sin_addr >> 0 ) & 0xff );
        message.push_back( ( sin_addr >> 8 ) & 0xff );
        message.push_back( ( sin_addr >> 16 ) & 0xff );
        message.push_back( ( sin_addr >> 24 ) & 0xff );
    }

    RDataPtr RecordA::parse( const uint8_t *begin, const uint8_t *end )
    {
        return RDataPtr( new RecordA( *( reinterpret_cast<const uint32_t *>( begin ) ) ) );
    }
}
