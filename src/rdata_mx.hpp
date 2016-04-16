#ifndef RDATA_MX_HPP
#define RDATA_MX_HPP

#include "dns.hpp"

namespace dns
{
    class RecordMX : public RData
    {
    private:
        uint16_t   priority;
        Domainname domainname;

    public:
        RecordMX( uint16_t pri, const Domainname &name );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_MX;
        }
        virtual uint16_t size() const
        {
            return sizeof( priority );
        }

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
