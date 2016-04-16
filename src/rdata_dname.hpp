#ifndef RDATA_DNAME_HPP
#define RDATA_DNAME_HPP

#include "dns.hpp"

namespace dns
{
    class RecordDNAME : public RData
    {
    private:
        Domainname domainname;

    public:
        RecordDNAME( const Domainname &name );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_DNAME;
        }
        virtual uint16_t size() const
        {
            return domainname.size();
        }

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
