#include "rdata_cname.hpp"

namespace dns
{
    RecordCNAME::RecordCNAME( const Domainname &name )
	: domainname( name )
    {
    }

    std::string RecordCNAME::toString() const
    {
        return domainname.toString();
    }

    void RecordCNAME::outputWireFormat( WireFormat &message ) const
    {
        domainname.outputWireFormat( message );
    }

    RDataPtr RecordCNAME::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet, begin );
        return RDataPtr( new RecordCNAME( name ) );
    }
}
