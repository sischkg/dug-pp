#ifndef RDATA_SOA_HPP
#define RDATA_SOA_HPP

#include "dns.hpp"

namespace dns
{
    class RecordSOA : public RData
    {
    private:
        Domainname mname;
        Domainname rname;
        uint32_t   serial;
        uint32_t   refresh;
        uint32_t   retry;
        uint32_t   expire;
        uint32_t   minimum;

    public:
        RecordSOA( const Domainname &mname,
                   const Domainname &rname,
                   uint32_t          serial,
                   uint32_t          refresh,
                   uint32_t          retry,
                   uint32_t          expire,
                   uint32_t          minimum );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_SOA;
        }
        virtual uint16_t size() const;

        const std::string getMName() const
        {
            return mname.toString();
        }
        const std::string getRName() const
        {
            return rname.toString();
        }

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
