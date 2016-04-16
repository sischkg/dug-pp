#ifndef RDATA_NS_HPP
#define RDATA_NS_HPP

#include "dns.hpp"

namespace dns
{
    class RecordNS : public RData
    {
    private:
        Domainname domainname;

    public:
        RecordNS( const Domainname &name );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_NS;
        }
        virtual uint16_t size() const
        {
            return domainname.size();
        }

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
