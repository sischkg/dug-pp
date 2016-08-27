#ifndef DNS_HPP
#define DNS_HPP

#include "utils.hpp"
#include "wireformat.hpp"
#include <stdexcept>
#include <string>
#include <vector>

#include "wireformat.hpp"
#include "dns_base.hpp"
#include "rdata.hpp"

namespace dns
{
    struct QuestionSectionEntry {
        Domainname domainname;
        uint16_t   type       = 0;
        uint16_t   klass      = 0;
    };

    struct ResponseSectionEntry {
        Domainname domainname;
        uint16_t   type  = 0;
        uint16_t   klass = 0;
        uint32_t   ttl   = 0;
        RDataPtr   rdata;
    };

    struct MessageInfo {
        uint16_t id;

        uint8_t query_response;
        uint8_t opcode;
        bool    authoritative_answer;
        bool    truncation;
        bool    recursion_desired;

        bool    recursion_available;
        bool    checking_disabled;
        bool    zero_field;
        bool    authentic_data;
        uint8_t response_code;

        bool edns0;
        bool tsig;

        OptPseudoRecord opt_pseudo_rr;
        RecordTSIG      tsig_rr;

        std::vector<QuestionSectionEntry> question_section;
        std::vector<ResponseSectionEntry> answer_section;
        std::vector<ResponseSectionEntry> authority_section;
        std::vector<ResponseSectionEntry> additional_infomation_section;

        MessageInfo()
            : id( 0 ), query_response( 0 ), opcode( 0 ), authoritative_answer( 0 ), truncation( false ),
              recursion_desired( false ), recursion_available( false ), checking_disabled( false ), zero_field( 0 ),
              authentic_data( false ), response_code( 0 ), edns0( false ), tsig( false )
        {
        }
    };

    void generateDNSMessage( const MessageInfo &message, WireFormat & );
    MessageInfo parseDNSMessage( const uint8_t *begin, const uint8_t *end );
    std::ostream &operator<<( std::ostream &os, const MessageInfo &packet_info );
    std::ostream &printHeader( std::ostream &os, const MessageInfo &packet );
    std::string TypeCodeTiString( Type t );
    std::string ResponseCodeToString( uint8_t rcode );

    void generateQuestionSection( const QuestionSectionEntry &q, WireFormat &message );
    void generateResponseSection( const ResponseSectionEntry &r, WireFormat &message );

    typedef std::pair<QuestionSectionEntry, const uint8_t *> QuestionSectionEntryPair;
    typedef std::pair<ResponseSectionEntry, const uint8_t *> ResponseSectionEntryPair;
    QuestionSectionEntryPair parseQuestionSection( const uint8_t *packet, const uint8_t *section );
    ResponseSectionEntryPair parseResponseSection( const uint8_t *packet, const uint8_t *section );

}

#endif
