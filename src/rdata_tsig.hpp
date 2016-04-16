#ifndef RDATA_TSIG_HPP
#define RDATA_TSIG_HPP

#include "rdata_base.hpp"

namespace dns
{
    struct TSIGInfo {
        std::string name;
        PacketData  key;
        std::string algorithm;
        PacketData  mac;
        uint64_t    signed_time;
        uint16_t    fudge;
        uint16_t    mac_size;
        uint16_t    original_id;
        uint16_t    error;
        PacketData  other;

        TSIGInfo()
            : name(), key(), algorithm( "HMAC-MD5.SIG-ALG.REG.INT" ), mac(), signed_time( 0 ), fudge( 0 ),
              mac_size( 0 ), original_id( 0 ), error( 0 ), other()
        {
        }
    };

    class RecordTSIG : public RData
    {
    public:
        Domainname key_name     = "";
        Domainname algorithm    = "HMAC-MD5.SIG-ALG.REG.INT";
        uint64_t   signed_time  = 0;
        uint16_t   fudge        = 0;
        uint16_t   mac_size     = 0;
        PacketData mac;
        uint16_t   original_id  = 0;
        uint16_t   error        = 0;
        uint16_t   other_length = 0;
        PacketData other;

    public:
        RecordTSIG( const std::string &in_key_name     = "",
		    const std::string &in_algo         = "HMAC-MD5.SIG-ALG.REG.INT",
		    uint64_t           in_signed_time  = 0,
		    uint16_t           in_fudge        = 0,
		    uint16_t           in_mac_size     = 0,
		    const PacketData & in_mac          = PacketData(),
		    uint16_t           in_original_id  = 0,
		    uint16_t           in_error        = 0,
		    uint16_t           in_other_length = 0,
		    const PacketData & in_other        = PacketData() )
	: key_name( in_key_name ), algorithm( in_algo ), signed_time( in_signed_time ), fudge( in_fudge ),
	    mac_size( in_mac_size ), mac( in_mac ), original_id( in_original_id ), error( in_error ),
	    other_length( in_other_length ), other( in_other )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    type() const
        {
            return TYPE_TSIG;
        }
        virtual uint16_t size() const;

        static RDataPtr
        parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end, const Domainname &key_name );
    };

    struct MessageInfo;
    void addTSIGResourceRecord( const TSIGInfo &tsig_info, WireFormat &message, const PacketData &query_mac = PacketData() );
    bool verifyTSIGResourceRecord( const TSIGInfo &tsig_info, const MessageInfo &packet_info, const WireFormat &message );

}

#endif
