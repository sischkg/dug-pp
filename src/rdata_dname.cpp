#include "rdata_dname.hpp"

namespace dns
{
    RecordDNAME::RecordDNAME( const Domainname &name )
	: domainname( name )
    {
    }

    std::string RecordDNAME::toString() const
    {
        return domainname.toString();
    }

    void RecordDNAME::outputWireFormat( WireFormat &message ) const
    {
        domainname.outputWireFormat( message );
    }

    RDataPtr RecordDNAME::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet, begin );
        return RDataPtr( new RecordDNAME( name ) );
    }
}
