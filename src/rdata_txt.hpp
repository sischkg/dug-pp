#ifndef RDATA_TXT_HPP
#define RDATA_TXT_HPP

#include "dns.hpp"

namespace dns
{
    class RecordTXT : public RData
    {
    private:
        std::vector<std::string> data;

    public:
        RecordTXT( const std::string &data );
        RecordTXT( const std::vector<std::string> &data );

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_TXT;
        }
        virtual uint16_t size() const;

        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };
}

#endif
