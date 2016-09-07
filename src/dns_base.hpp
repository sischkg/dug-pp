#ifndef DNS_BASE_HPP
#define DNS_BASE_HPP

#include <memory>
#include "domainname.hpp"

namespace dns
{
    typedef uint8_t Opcode;
    const Opcode    OPCODE_QUERY  = 0;
    const Opcode    OPCODE_NOTIFY = 4;
    const Opcode    OPCODE_UPDATE = 5;

    typedef uint16_t Class;
    const Class      CLASS_IN      = 1;
    const Class      CLASS_ANY     = 255;
    const Class      UPDATE_NONE   = 254;
    const Class      UPDATE_EXIST  = 255;
    const Class      UPDATE_ADD    = 1;
    const Class      UPDATE_DELETE = 255;

    typedef uint16_t Type;
    const Type       TYPE_A      = 1;
    const Type       TYPE_NS     = 2;
    const Type       TYPE_CNAME  = 5;
    const Type       TYPE_SOA    = 6;
    const Type       TYPE_MX     = 15;
    const Type       TYPE_TXT    = 16;
    const Type       TYPE_KEY    = 25;
    const Type       TYPE_AAAA   = 28;
    const Type       TYPE_NAPTR  = 35;
    const Type       TYPE_DNAME  = 39;
    const Type       TYPE_OPT    = 41;
    const Type       TYPE_APL    = 42;
    const Type       TYPE_DNSKEY = 48;
    const Type       TYPE_TLSA   = 52;
    const Type       TYPE_TKEY   = 249;
    const Type       TYPE_TSIG   = 250;
    const Type       TYPE_IXFR   = 251;
    const Type       TYPE_AXFR   = 252;
    const Type       TYPE_ANY    = 255;

    typedef uint16_t OptType;
    const OptType    OPT_NSID          = 3;
    const OptType    OPT_CLIENT_SUBNET = 8;

    typedef uint8_t    ResponseCode;
    const ResponseCode NO_ERROR       = 0;
    const ResponseCode NXRRSET        = 0;
    const ResponseCode FORMAT_ERROR   = 1;
    const ResponseCode SERVER_ERROR   = 2;
    const ResponseCode NAME_ERROR     = 3;
    const ResponseCode NXDOMAIN       = 3;
    const ResponseCode NOT_IMPLEENTED = 4;
    const ResponseCode REFUSED        = 5;
    const ResponseCode BADSIG         = 16;
    const ResponseCode BADKEY         = 17;
    const ResponseCode BADTIME        = 18;

    typedef uint8_t ResponseType;
    const ResponseType RESPONSE_SUCCESS  = 0;
    const ResponseType RESPONSE_NXDOMAIN = 1;
    const ResponseType RESPONSE_NODATA   = 2;
    const ResponseType RESPONSE_CNAME    = 3;
    const ResponseType RESPONSE_REFERRAL = 4;
    
    class ResourceData;
    typedef std::shared_ptr<ResourceData> ResourceDataPtr;

    /*!
     * DNS Packetのフォーマットエラーを検知した場合にthrowする例外
     */
    class FormatError : public std::runtime_error
    {
    public:
        FormatError( const std::string &msg ) : std::runtime_error( msg )
        {
        }
    };

    struct PacketHeaderField {
        uint16_t id;

        uint8_t recursion_desired : 1;
        uint8_t truncation : 1;
        uint8_t authoritative_answer : 1;
        uint8_t opcode : 4;
        uint8_t query_response : 1;

        uint8_t response_code : 4;
        uint8_t checking_disabled : 1;
        uint8_t authentic_data : 1;
        uint8_t zero_field : 1;
        uint8_t recursion_available : 1;

        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t additional_infomation_count;
    };


    template <typename Type>
    uint8_t *set_bytes( Type v, uint8_t *pos )
    {
        *reinterpret_cast<Type *>( pos ) = v;
        return pos + sizeof( v );
    }

    template <typename Type>
    Type get_bytes( const uint8_t **pos )
    {
        Type v = *reinterpret_cast<const Type *>( *pos );
        *pos += sizeof( Type );
        return v;
    }
}

#endif
