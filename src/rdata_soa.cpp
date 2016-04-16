#include "rdata_soa.hpp"
#include <sstream>

namespace dns
{
    struct SOAField {
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
    };

    RecordSOA::RecordSOA( const Domainname &mn,
                          const Domainname &rn,
                          uint32_t          sr,
                          uint32_t          rf,
                          uint32_t          rt,
                          uint32_t          ex,
                          uint32_t          min )
        : mname( mn ), rname( rn ), serial( sr ), refresh( rf ), retry( rt ), expire( ex ), minimum( min )
    {
    }

    std::string RecordSOA::toString() const
    {
        std::ostringstream soa_str;
        soa_str << mname.toString() << " " << rname.toString() << " " << serial << " " << refresh << " " << retry << " "
                << expire << " " << minimum;
        return soa_str.str();
    }

    void RecordSOA::outputWireFormat( WireFormat &message ) const
    {
        mname.outputWireFormat( message );
        rname.outputWireFormat( message );
        message.pushUInt32HtoN( serial );
        message.pushUInt32HtoN( refresh );
        message.pushUInt32HtoN( retry );
        message.pushUInt32HtoN( expire );
        message.pushUInt32HtoN( minimum );
    }

    uint16_t RecordSOA::size() const
    {
        return mname.size() + rname.size() + sizeof( serial ) + sizeof( refresh ) +
               sizeof( retry ) + sizeof( expire ) + sizeof( minimum );
    }

    RDataPtr RecordSOA::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname     mname_result, rname_result;
        const uint8_t *pos = begin;
        pos                = Domainname::parsePacket( mname_result, packet, pos );
        pos                = Domainname::parsePacket( rname_result, packet, pos );
        uint32_t serial    = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t refresh   = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t retry     = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t expire    = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t minimum   = ntohl( get_bytes<uint32_t>( &pos ) );

        return RDataPtr( new RecordSOA( mname_result, rname_result, serial, refresh, retry, expire, minimum ) );
    }
}
