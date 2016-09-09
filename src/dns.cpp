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
    void generateDNSMessage( const MessageInfo &info, WireFormat &message )
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

	uint16_t additional_count = info.additional_infomation_section.size();
	if ( info.edns0 )
	    additional_count++;
	
        header.question_count              = htons( info.question_section.size() );
        header.answer_count                = htons( info.answer_section.size() );
        header.authority_count             = htons( info.authority_section.size() );
        header.additional_infomation_count = htons( additional_count );

        message.pushBuffer( reinterpret_cast<const uint8_t *>( &header ),
                            reinterpret_cast<const uint8_t *>( &header ) + sizeof( header ) );

        for ( auto &query : info.question_section )
            generateQuestionSection( query, message );
 
        for ( auto &answer : info.answer_section )
            generateResponseSection( answer, message );
	
        for ( auto &auth : info.authority_section )
            generateResponseSection( auth, message );

        for ( auto &add : additional )
            generateResponseSection( add, message );

	if ( info.edns0 )
	    info.opt_pseudo_rr.outputWireFormat( message );
    }

    MessageInfo parseDNSMessage( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *packet = begin;

        MessageInfo              packet_info;
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
            QuestionSectionEntryPair pair = parseQuestionSection( begin, packet );
            packet_info.question_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < answer_count; i++ ) {
            ResponseSectionEntryPair pair = parseResponseSection( begin, packet );
            packet_info.answer_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < authority_count; i++ ) {
            ResponseSectionEntryPair pair = parseResponseSection( begin, packet );
            packet_info.authority_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < additional_infomation_count; i++ ) {
            ResponseSectionEntryPair pair = parseResponseSection( begin, packet );
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


    void generateQuestionSection( const QuestionSectionEntry &question, WireFormat &message )
    {
        question.domainname.outputWireFormat( message );
        message.pushUInt16HtoN( question.type );
        message.pushUInt16HtoN( question.klass );
    }

    QuestionSectionEntryPair parseQuestionSection( const uint8_t *packet, const uint8_t *p )
    {
        QuestionSectionEntry question;
        const uint8_t *      pos = Domainname::parsePacket( question.domainname, packet, p );

        question.type  = ntohs( get_bytes<uint16_t>( &pos ) );
        question.klass = ntohs( get_bytes<uint16_t>( &pos ) );

        return QuestionSectionEntryPair( question, pos );
    }

    void generateResponseSection( const ResponseSectionEntry &response, WireFormat &message )
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

    ResponseSectionEntryPair parseResponseSection( const uint8_t *packet, const uint8_t *begin )
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

    std::ostream &printHeader( std::ostream &os, const MessageInfo &message )
    {
        os << "ID:                   " << message.id                   << std::endl
           << "Query/Response:       " << ( message.query_response == 0 ? "Query" : "Response" ) << std::endl
           << "OpCode:               " << static_cast<uint16_t>( message.opcode )                << std::endl
           << "Authoritative Answer: " << message.authoritative_answer << std::endl
           << "Truncation:           " << message.truncation           << std::endl
           << "Recursion Desired:    " << message.recursion_desired    << std::endl
           << "Recursion Available:  " << message.recursion_available  << std::endl
           << "Checking Disabled:    " << message.checking_disabled    << std::endl
           << "Response Code:        " << ResponseCodeToString( message.response_code ) << std::endl;

        return os;
    }

    std::ostream &operator<<( std::ostream &os, const MessageInfo &message )
    {
	printHeader( os, message );

        for ( auto &entry : message.question_section )
            os << "Query: " << entry.domainname << " " << TypeCodeToString( entry.type ) << "  ?" << std::endl;
        for ( auto &entry : message.answer_section )
            std::cout << "Answer: " << entry.domainname << " " << entry.ttl << " " << TypeCodeToString( entry.type )
                      << " " << entry.rdata->toString() << std::endl;
	for ( auto &entry : message.authority_section )
	    std::cout << "Authority: " << entry.ttl << " " << TypeCodeToString( entry.type ) << " "
                      << entry.rdata->toString() << std::endl;
        for ( auto &entry : message.additional_infomation_section )
            std::cout << "Additional: " << entry.domainname << " " << entry.ttl << " " << TypeCodeToString( entry.type )
                      << " " << entry.rdata->toString() << std::endl;

        return os;
    }

    struct TypeToString {
	Type type;
	const char *name;
    };


    const TypeToString typeToString[] = {
	{ TYPE_A,      "A" },
	{ TYPE_NS,     "NS" },
	{ TYPE_CNAME,  "CNAME" },
	{ TYPE_NAPTR,  "NAPTR" },
	{ TYPE_DNAME,  "DNAME" },
	{ TYPE_MX,     "MX" },
	{ TYPE_TXT,    "TXT" },
	{ TYPE_SOA,    "SOA" },
	{ TYPE_KEY,    "KEY" },
	{ TYPE_AAAA,   "AAAA" },
	{ TYPE_OPT,    "OPT" },
	{ TYPE_DNSKEY, "DNSKEY" },
	{ TYPE_TSIG,   "TSIG" },
	{ TYPE_TKEY,   "TKEY" },
	{ TYPE_IXFR,   "IXFR" },
	{ TYPE_AXFR,   "AXFR" },
	{ TYPE_ANY,    "ANY" },
    };

    Type StringToTypeCode( const std::string &str )
    {
	const std::string type_str = toUpper( str );
	for ( auto t2s : typeToString ) {
	    if ( type_str == t2s.name )
		return t2s.type;
	}
	throw std::runtime_error( "unknown type " + str );
    }

    std::string TypeCodeToString( Type type )
    {
	for ( auto t2s : typeToString ) {
	    if ( type == t2s.type )
		return t2s.name;
	}
	return boost::lexical_cast<std::string>( type );
    }

    std::string ResponseCodeToString( uint8_t rcode )
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

    ResponseType classifyResponse( const MessageInfo &response )
    {
	if ( response.question_section.size() != 1 )
	    std::logic_error( "qd_count must be 1" );
	const QuestionSectionEntry &question = response.question_section[0];
	
	if ( response.response_code == NXDOMAIN ) {
	    return RESPONSE_NXDOMAIN;
	}
	if ( response.response_code == NO_ERROR ) {
	    bool is_cname   = false;
	    bool is_success = false;
	    for( auto &answer : response.answer_section ) {
		if ( question.domainname == answer.domainname &&
		     question.type       == answer.type &&
		     question.klass      == answer.klass ) {
		    is_success = true;
		}
		if ( question.domainname == answer.domainname &&
		     TYPE_CNAME          == answer.type &&
		     question.klass      == answer.klass ) {
		    is_cname = true;
		}
	    }
	    if ( is_cname )
		return RESPONSE_CNAME;
	    if ( is_success )
		return RESPONSE_SUCCESS;

	    if ( response.answer_section.size() == 0 ) {
		bool is_referral = false;
		for( auto &auth : response.authority_section ) {
		    if ( auth.type  == TYPE_NS &&
			 auth.klass == question.klass ) {
			if ( auth.domainname == question.domainname ||
			     auth.domainname.isInternalName( question.domainname ) ) {
			    is_referral = true;
			}
		    }
		}
		if ( is_referral )
		    return RESPONSE_REFERRAL;
		else
		    return RESPONSE_NODATA;
	    }
	}

	throw std::runtime_error( "cannot classify response message" );
    }


    std::string ResponseTypeString( ResponseType type )
    {
	switch ( type ) {
	case RESPONSE_SUCCESS:
	    return "SUCCESS";
	case RESPONSE_NXDOMAIN:
	    return "NXDOMAIN";
	case RESPONSE_CNAME:
	    return "CNAME";
	case RESPONSE_REFERRAL:
	    return "REFERRAL";
	case RESPONSE_NODATA:
	    return "NODATA";
	}
	return "UNKNOWN";
    }

}
