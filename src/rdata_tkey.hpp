#ifndef RDATA_TKEY_HPP
#define RDATA_TKEY_HPP

#include "dns.hpp"

namespace dns
{
    class RecordTKey : public RData
    {
    public:
        Domainname domain;
        Domainname algorithm;
        uint32_t   inception;
        uint32_t   expiration;
        uint16_t   mode;
        uint16_t   error;
        PacketData key;
        PacketData other_data;

    public:
        RecordTKey( const std::string &dom    = "",
                    const std::string &algo   = "HMAC-MD5.SIG-ALG.REG.INT",
                    uint32_t           incept = 0,
                    uint32_t           expire = 0,
                    uint16_t           m      = 0,
                    uint16_t           err    = 0,
                    PacketData         k      = PacketData(),
                    PacketData         other  = PacketData() )
            : domain( dom ), algorithm( algo ), inception( incept ), expiration( expire ), mode( m ), error( err ),
	    key( k ), other_data( other )
        {
        }

        virtual std::string toString() const
        {
            return "";
        }
        virtual void     outputWireFormat( WireFormat & ) const;
        virtual uint16_t type() const
        {
            return TYPE_TKEY;
        }
        virtual uint16_t size() const;
    };
}

#endif
