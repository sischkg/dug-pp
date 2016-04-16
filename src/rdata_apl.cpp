#include "rdata_apl.hpp"
#include <sstream>

namespace dns
{
    std::string RecordAPL::toString() const
    {
        std::ostringstream os;
        for ( auto i = apl_entries.begin(); i != apl_entries.end(); i++ ) {
            os << ( i->negation ? "!" : "" ) << i->address_family << ":" << printPacketData( i->afd ) << " ";
        }
        return os.str();
    }

    void RecordAPL::outputWireFormat( WireFormat &message ) const
    {
        for ( auto i = apl_entries.begin(); i != apl_entries.end(); i++ ) {
            message.pushUInt16HtoN( i->address_family );
            message.pushUInt8( i->prefix );
            message.pushUInt8( ( i->negation ? ( 1 << 7 ) : 0 ) | i->afd.size() );
            message.pushBuffer( i->afd );
        }
    }

    uint16_t RecordAPL::size() const
    {
        uint16_t s = 0;
        for ( auto i = apl_entries.begin(); i != apl_entries.end(); i++ ) {
            s += ( 2 + 1 + 1 + i->afd.size() );
        }
        return s;
    }

    RDataPtr RecordAPL::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        std::vector<APLEntry> entries;
        const uint8_t *       pos = begin;

        while ( pos < end ) {
            if ( end - pos < 4 )
                throw FormatError( "too short length of APL RDdata" );

            APLEntry entry;
            entry.address_family = ntohs( get_bytes<uint16_t>( &pos ) );
            entry.prefix         = get_bytes<uint8_t>( &pos );
            uint8_t neg_afd_len  = get_bytes<uint8_t>( &pos );
            entry.negation       = ( neg_afd_len & 0x01 ) == 0x01;
            uint8_t afd_length   = ( neg_afd_len >> 1 );

            if ( end - pos < afd_length )
                throw FormatError( "invalid AFD Data length" );

            PacketData in_afd;
            entry.afd.insert( in_afd.end(), pos, pos + afd_length );
            pos += afd_length;
            entries.push_back( entry );
        }

        return RDataPtr( new RecordAPL( entries ) );
    }
}
