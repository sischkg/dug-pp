#include "rdata_naptr.hpp"
#include <sstream>

namespace dns
{
    RecordNAPTR::RecordNAPTR( uint16_t           in_order,
                              uint16_t           in_preference,
                              const std::string &in_flags,
                              const std::string &in_services,
                              const std::string &in_regexp,
                              const Domainname & in_replacement )
        : order( in_order ), preference( in_preference ), flags( in_flags ), services( in_services ),
          regexp( in_regexp ), replacement( in_replacement )
    {
    }

    std::string RecordNAPTR::toString() const
    {
        std::stringstream os;
        os << "order: " << order << ", preference: " << preference << "flags: " << flags << ", services: " << services
           << "regexp: " << regexp << ", replacement: " << replacement;
        return os.str();
    }

    void RecordNAPTR::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( order );
        message.pushUInt16HtoN( preference );
        message.pushUInt8( flags.size() );
        message.pushBuffer( reinterpret_cast<const uint8_t *>( flags.c_str() ),
                            reinterpret_cast<const uint8_t *>( flags.c_str() ) + flags.size() );
        message.pushUInt8( regexp.size() );
        message.pushBuffer( reinterpret_cast<const uint8_t *>( regexp.c_str() ),
                            reinterpret_cast<const uint8_t *>( regexp.c_str() ) + regexp.size() );
        replacement.outputWireFormat( message );
    }

    uint16_t RecordNAPTR::size() const
    {
        return sizeof( order ) + sizeof( preference ) + 1 + flags.size() + 1 + regexp.size() +
	    replacement.size();
    }

    RDataPtr RecordNAPTR::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin < 2 + 2 + 1 + 1 + 1 + 1 )
            throw FormatError( "too short for NAPTR RR" );

        const uint8_t *pos           = begin;
        uint16_t       in_order      = ntohs( get_bytes<uint16_t>( &pos ) );
        uint16_t       in_preference = ntohs( get_bytes<uint16_t>( &pos ) );

        std::string in_flags, in_services, in_regexp;
        pos = parseCharacterString( pos, end, in_flags );
        pos = parseCharacterString( pos, end, in_services );
        pos = parseCharacterString( pos, end, in_regexp );

        Domainname in_replacement;
        Domainname::parsePacket( in_replacement, packet, pos );
        return RDataPtr(
            new RecordNAPTR( in_order, in_preference, in_flags, in_services, in_regexp, in_replacement ) );
    }
}
