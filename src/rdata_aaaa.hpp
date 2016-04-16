#ifndef RDATA_AAAA_HPP
#define RDATA_AAAA_HPP

#include "dns.hpp"

namespace dns
{
    class RecordAAAA : public RData
    {
    private:
        uint8_t sin_addr[ 16 ];

    public:
        RecordAAAA( const uint8_t *sin_addr );
        RecordAAAA( const std::string &address );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual Type type() const
        {
            return TYPE_AAAA;
        }
        virtual uint16_t size() const
        {
            return sizeof( sin_addr );
        }

        static RDataPtr parse( const uint8_t *begin, const uint8_t *end );
    };
}

#endif
