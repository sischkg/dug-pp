#include "rdata_mx.hpp"
#include <sstream>

namespace dns
{
    RecordMX::RecordMX( uint16_t pri, const Domainname &name )
        : priority( pri ), domainname( name )
    {
    }

    std::string RecordMX::toString() const
    {
        std::ostringstream os;
        os << priority << " " << domainname.toString();
        return os.str();
    }

    void RecordMX::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( priority );
        domainname.outputWireFormat( message );
    }

    RDataPtr RecordMX::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin < 3 )
            throw FormatError( "too few length for MX record," );
        const uint8_t *pos      = begin;
        uint16_t       priority = get_bytes<uint16_t>( &pos );

        Domainname name;
        Domainname::parsePacket( name, packet, pos );
        return RDataPtr( new RecordMX( priority, name ) );
    }
}
