#ifndef RDATA_DNSKEY_HPP
#define RDATA_DNSKEY_HPP

#include "dns.hpp"

namespace dns
{
    class RecordDNSKey : public RData
    {
    private:
        uint16_t             flags;
        uint8_t              algorithm;
        std::vector<uint8_t> public_key;

    public:
        static const uint16_t SIGNED_KEY = 1 << 7;
        static const uint8_t  RSAMD5     = 1;
        static const uint8_t  RSASHA1    = 5;
        static const uint8_t  RSASHA256  = 8;
        static const uint8_t  RSASHA512  = 10;

        RecordDNSKey( uint16_t f, uint8_t algo, const std::vector<uint8_t> key )
            : flags( f ), algorithm( algo ), public_key( key )
        {
        }

        virtual std::string toString() const
        {
            return "";
        }

        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const
        {
            return 2 + 1 + 1 + public_key.size();
        }

        virtual uint16_t type() const
        {
            return TYPE_DNSKEY;
        }

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
