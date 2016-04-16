#include "rdata_dnskey.hpp"

namespace dns
{
    void RecordDNSKey::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( flags );
        message.pushUInt8( 3 );
        message.pushUInt8( algorithm );
        message.pushBuffer( public_key );
    }

    RDataPtr RecordDNSKey::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *      pos   = begin;
        uint16_t             f     = ntohs( get_bytes<uint16_t>( &pos ) );
        uint8_t              proto = get_bytes<uint8_t>( &pos );
        uint8_t              algo  = get_bytes<uint8_t>( &pos );
        std::vector<uint8_t> key;
        key.insert( key.end(), pos, end );

        return RDataPtr( new RecordDNSKey( f, algo, key ) );
    }
}
