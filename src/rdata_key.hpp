#ifndef RDATA_KEY_HPP
#define RDATA_KEY_HPP

#include "dns.hpp"

namespace dns
{
    const uint8_t PROTOCOL_TLS    = 0x01;
    const uint8_t PROTOCOL_MAIL   = 0x02;
    const uint8_t PROTOCOL_DNSSEC = 0x03;
    const uint8_t PROTOCOL_IPSEC  = 0x04;
    const uint8_t PROTOCOL_ANY    = 0xFF;

    const uint8_t ALGORITHM_DH = 0x02;

    class RecordKey : public RData
    {
    public:
        uint8_t ac;
        uint8_t xt;
        uint8_t namtyp;
        uint8_t sig;

        uint8_t    protocol;
        uint8_t    algorithm;
        PacketData public_key;

    public:
        RecordKey( uint8_t in_ac        = 0,
                   uint8_t in_xt        = 0,
                   uint8_t in_namtyp    = 0,
                   uint8_t in_sig       = 0,
                   uint8_t in_protocol  = PROTOCOL_DNSSEC,
                   uint8_t in_algorithm = ALGORITHM_DH )
            : ac( 0 ), xt( 0 ), namtyp( 0 ), sig( 0 ), protocol( in_protocol ), algorithm( in_algorithm )
        {
        }

        virtual std::string toString() const
        {
            return "";
        }

        virtual void outputWireFormat( WireFormat &message )
        {
            message.pushUInt8( 0 );
            message.pushUInt8( 0 );
            message.pushUInt8( protocol );
            message.pushUInt8( algorithm );
        }
        virtual uint16_t size() const
        {
            return 4;
        }

        virtual uint16_t type() const
        {
            return TYPE_KEY;
        }
    };
}

#endif
