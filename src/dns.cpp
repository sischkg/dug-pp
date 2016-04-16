#include "dns.hpp"
#include "rdata.hpp"
#include "utils.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <endian.h>

namespace dns
{
    void generate_dns_packet( const MessageInfo &info, WireFormat &message )
    {
        PacketHeaderField header;
        header.id                   = htons( info.id );
        header.opcode               = info.opcode;
        header.query_response       = info.query_response;
        header.authoritative_answer = info.authoritative_answer;
        header.truncation           = info.truncation;
        header.recursion_desired    = info.recursion_desired;
        header.recursion_available  = info.recursion_available;
        header.zero_field           = 0;
        header.authentic_data       = info.authentic_data;
        header.checking_disabled    = info.checking_disabled;
        header.response_code        = info.response_code;

        std::vector<ResponseSectionEntry> additional = info.additional_infomation_section;

        if ( info.edns0 ) {
            additional.push_back( generate_opt_pseudo_record( info.opt_pseudo_rr ) );
        }

        header.question_count              = htons( info.question_section.size() );
        header.answer_count                = htons( info.answer_section.size() );
        header.authority_count             = htons( info.authority_section.size() );
        header.additional_infomation_count = htons( additional.size() );

        message.pushBuffer( reinterpret_cast<const uint8_t *>( &header ),
                            reinterpret_cast<const uint8_t *>( &header ) + sizeof( header ) );

        for ( auto q = info.question_section.begin(); q != info.question_section.end(); ++q ) {
            generate_question_section( *q, message );
        }
        for ( auto q = info.answer_section.begin(); q != info.answer_section.end(); ++q ) {
            generate_response_section( *q, message );
        }
        for ( auto q = info.authority_section.begin(); q != info.authority_section.end(); ++q ) {
            generate_response_section( *q, message );
        }
        for ( auto q = additional.begin(); q != additional.end(); ++q ) {
            generate_response_section( *q, message );
        }
    }

    MessageInfo parse_dns_packet( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *packet = begin;

        MessageInfo               packet_info;
        const PacketHeaderField *header = reinterpret_cast<const PacketHeaderField *>( begin );

        packet_info.id                   = ntohs( header->id );
        packet_info.query_response       = header->query_response;
        packet_info.opcode               = header->opcode;
        packet_info.authoritative_answer = header->authoritative_answer;
        packet_info.truncation           = header->truncation;
        packet_info.recursion_available  = header->recursion_available;
        packet_info.recursion_desired    = header->recursion_desired;
        packet_info.checking_disabled    = header->checking_disabled;
        packet_info.authentic_data       = header->authentic_data;
        packet_info.response_code        = header->response_code;

        int question_count              = ntohs( header->question_count );
        int answer_count                = ntohs( header->answer_count );
        int authority_count             = ntohs( header->authority_count );
        int additional_infomation_count = ntohs( header->additional_infomation_count );

        packet += sizeof( PacketHeaderField );
        for ( int i = 0; i < question_count; i++ ) {
            QuestionSectionEntryPair pair = parse_question_section( begin, packet );
            packet_info.question_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < answer_count; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            packet_info.answer_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < authority_count; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            packet_info.authority_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < additional_infomation_count; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            if ( pair.first.type == TYPE_OPT ) {
                packet_info.edns0 = true;
            }
            if ( pair.first.type == TYPE_TSIG && pair.first.klass == CLASS_IN ) {
                packet_info.tsig    = true;
                packet_info.tsig_rr = dynamic_cast<const RecordTSIG &>( *( pair.first.rdata ) );
            }
            packet_info.additional_infomation_section.push_back( pair.first );
            packet = pair.second;
        }

        return packet_info;
    }


    void generate_question_section( const QuestionSectionEntry &question, WireFormat &message )
    {
        question.domainname.outputWireFormat( message );
        message.pushUInt16HtoN( question.type );
        message.pushUInt16HtoN( question.klass );
    }

    QuestionSectionEntryPair parse_question_section( const uint8_t *packet, const uint8_t *p )
    {
        QuestionSectionEntry question;
        const uint8_t *      pos = Domainname::parsePacket( question.domainname, packet, p );

        question.type  = ntohs( get_bytes<uint16_t>( &pos ) );
        question.klass = ntohs( get_bytes<uint16_t>( &pos ) );

        return QuestionSectionEntryPair( question, pos );
    }

    void generate_response_section( const ResponseSectionEntry &response, WireFormat &message )
    {
        response.domainname.outputWireFormat( message  );
        message.pushUInt16HtoN( response.type );
        message.pushUInt16HtoN( response.klass );
        message.pushUInt32HtoN( response.ttl );
        if ( response.rdata ) {
            message.pushUInt16HtoN( response.rdata->size() );
            response.rdata->outputWireFormat( message );
        } else {
            message.pushUInt16HtoN( 0 );
        }
    }

    ResponseSectionEntryPair parse_response_section( const uint8_t *packet, const uint8_t *begin )
    {
        ResponseSectionEntry sec;

        const uint8_t *pos   = Domainname::parsePacket( sec.domainname, packet, begin );
        sec.type           = ntohs( get_bytes<uint16_t>( &pos ) );
        sec.klass          = ntohs( get_bytes<uint16_t>( &pos ) );
        sec.ttl            = ntohl( get_bytes<uint32_t>( &pos ) );
        uint16_t data_length = ntohs( get_bytes<uint16_t>( &pos ) );

        RDataPtr parsed_data;
        switch ( sec.type ) {
        case TYPE_A:
            parsed_data = RecordA::parse( pos, pos + data_length );
            break;
        case TYPE_AAAA:
            parsed_data = RecordAAAA::parse( pos, pos + data_length );
            break;
        case TYPE_NS:
            parsed_data = RecordNS::parse( packet, pos, pos + data_length );
            break;
        case TYPE_CNAME:
            parsed_data = RecordCNAME::parse( packet, pos, pos + data_length );
            break;
        case TYPE_NAPTR:
            parsed_data = RecordNAPTR::parse( packet, pos, pos + data_length );
            break;
        case TYPE_DNAME:
            parsed_data = RecordDNAME::parse( packet, pos, pos + data_length );
            break;
        case TYPE_MX:
            parsed_data = RecordMX::parse( packet, pos, pos + data_length );
            break;
        case TYPE_TXT:
            parsed_data = RecordTXT::parse( packet, pos, pos + data_length );
            break;
        case TYPE_SOA:
            parsed_data = RecordSOA::parse( packet, pos, pos + data_length );
            break;
        case TYPE_DNSKEY:
            parsed_data = RecordDNSKey::parse( packet, pos, pos + data_length );
            break;
        case TYPE_TSIG:
            parsed_data = RecordTSIG::parse( packet, pos, pos + data_length, sec.domainname );
            break;
        case TYPE_OPT:
            parsed_data = RecordOptionsData::parse( packet, pos, pos + data_length );
            break;
        default:
            std::ostringstream msg;
            msg << "not support type \"" << sec.type << "\".";
            throw std::runtime_error( msg.str() );
        }
        pos += data_length;

        sec.rdata = parsed_data;
        return ResponseSectionEntryPair( sec, pos );
    }

    std::ostream &print_header( std::ostream &os, const MessageInfo &packet )
    {
        os << "ID:                   " << packet.id                   << std::endl
           << "Query/Response:       " << ( packet.query_response == 0 ? "Query" : "Response" ) << std::endl
           << "OpCode:               " << packet.opcode               << std::endl
           << "Authoritative Answer: " << packet.authoritative_answer << std::endl
           << "Truncation:           " << packet.truncation           << std::endl
           << "Recursion Desired:    " << packet.recursion_desired    << std::endl
           << "Recursion Available:  " << packet.recursion_available  << std::endl
           << "Checking Disabled:    " << packet.checking_disabled    << std::endl
           << "Response Code:        " << response_code_to_string( packet.response_code ) << std::endl;

        return os;
    }

    std::string type_code_to_string( Type t )
    {
        std::string res;

        switch ( t ) {
        case TYPE_A:
            res = "A";
            break;
        case TYPE_NS:
            res = "NS";
            break;
        case TYPE_CNAME:
            res = "CNAME";
            break;
        case TYPE_NAPTR:
            res = "NAPTR";
            break;
        case TYPE_DNAME:
            res = "DNAME";
            break;
        case TYPE_MX:
            res = "MX";
            break;
        case TYPE_TXT:
            res = "TXT";
            break;
        case TYPE_SOA:
            res = "SOA";
            break;
        case TYPE_KEY:
            res = "KEY";
            break;
        case TYPE_AAAA:
            res = "AAAA";
            break;
        case TYPE_OPT:
            res = "OPT";
            break;
        case TYPE_DNSKEY:
            res = "DNSKEY";
            break;
        case TYPE_TSIG:
            res = "TSIG";
            break;
        case TYPE_TKEY:
            res = "TKEY";
            break;
        case TYPE_IXFR:
            res = "IXFR";
            break;
        case TYPE_AXFR:
            res = "AXFR";
            break;
        case TYPE_ANY:
            res = "ANY";
            break;
        default:
            res = boost::lexical_cast<std::string>( t );
        }
        return res;
    }

    std::string response_code_to_string( uint8_t rcode )
    {
        std::string res;

        const char *rcode2str[] = {
            "NoError   No Error",
            "FormErr   Format Error",
            "ServFail  Server Failure",
            "NXDomain  Non-Existent Domain",
            "NotImp    Not Implemented",
            "Refused   Query Refused",
            "YXDomain  Name Exists when it should not",
            "YXRRSet   RR Set Exists when it should not",
            "NXRRSet   RR Set that should exist does not",
            "NotAuth   Server Not Authoritative for zone",
            "NotZone   Name not contained in zone",
            "11        available for assignment",
            "12        available for assignment",
            "13        available for assignment",
            "14        available for assignment",
            "15        available for assignment",
            "BADVERS   Bad OPT Version",
            "BADSIG    TSIG Signature Failure",
            "BADKEY    Key not recognized",
            "BADTIME   Signature out of time window",
            "BADMODE   Bad TKEY Mode",
            "BADNAME   Duplicate key name",
            "BADALG    Algorithm not supported",
        };

        if ( rcode < sizeof( rcode2str ) / sizeof( char * ) )
            res = rcode2str[ rcode ];
        else
            res = "n         available for assignment";

        return res;
    }

}
