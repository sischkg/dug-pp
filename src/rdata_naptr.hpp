#ifndef RDATA_NAPTR_HPP
#define RDATA_NAPTR_HPP

#include "dns.hpp"

namespace dns
{
    class RecordNAPTR : public RData
    {
    private:
        uint16_t    order;
        uint16_t    preference;
        std::string flags;
        std::string services;
        std::string regexp;
        Domainname  replacement;

    public:
        RecordNAPTR( uint16_t           in_order,
                     uint16_t           in_preference,
                     const std::string &in_flags,
                     const std::string &in_services,
                     const std::string &in_regexp,
                     const Domainname & in_replacement );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_NAPTR;
        }
        virtual uint16_t size() const;

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
