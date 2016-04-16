#ifndef RDATA_APL_HPP
#define RDATA_APL_HPP

#include "dns.hpp"

namespace dns
{
    struct APLEntry {
        uint16_t   address_family;
        uint8_t    prefix;
        bool       negation;
        PacketData afd;
    };

    class RecordAPL : public RData
    {
    private:
        std::vector<APLEntry> apl_entries;

    public:
        static const uint16_t IPv4    = 1;
        static const uint16_t IPv6    = 2;
        static const uint16_t Invalid = 0xffff;

        RecordAPL( const std::vector<APLEntry> &in_apls ) : apl_entries( in_apls )
        {
        }

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_APL;
        }
        virtual uint16_t size() const;

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
