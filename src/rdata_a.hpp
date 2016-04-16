#ifndef RDATA_A_HPP
#define RDATA_A_HPP

#include "dns.hpp"

namespace dns
{
    class RecordA : public RData
    {
    private:
        uint32_t sin_addr;

    public:
        RecordA( uint32_t in_sin_addr );
        RecordA( const std::string &in_address );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual Type type() const
        {
            return TYPE_A;
        }
        virtual uint16_t size() const
        {
            return sizeof( sin_addr );
        }
        static RDataPtr parse( const uint8_t *begin, const uint8_t *end );
    };
}

#endif
