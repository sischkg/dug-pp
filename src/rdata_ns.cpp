#include "rdata_ns.hpp"

namespace dns
{
    RecordNS::RecordNS( const Domainname &name )
	: domainname( name )
    {
    }

    std::string RecordNS::toString() const
    {
        return domainname.toString();
    }

    void RecordNS::outputWireFormat( WireFormat &message ) const
    {
        domainname.outputWireFormat( message );
    }

    RDataPtr RecordNS::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet, begin );
        return RDataPtr( new RecordNS( name ) );
    }
}
