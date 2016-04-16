#ifndef RDATA_CNAME_HPP
#define RDATA_CNAME_HPP

#include "dns.hpp"

namespace dns
{
    class RecordCNAME : public RData
    {
    private:
        Domainname domainname;

    public:
        RecordCNAME( const Domainname &name );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_CNAME;
        }
        virtual uint16_t size() const
        {
            return domainname.size();
        }

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
