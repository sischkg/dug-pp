#include "dns.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class StringToType : public ::testing::Test
{
public:

};

TEST_F( StringToType, convert_a_to_type_a )
{
    EXPECT_EQ( "A",      dns::TypeCodeToString( dns::TYPE_A ) )      << "'A'      -> TYPE_A";
    EXPECT_EQ( "NS",     dns::TypeCodeToString( dns::TYPE_NS ) )     << "'NS'     -> TYPE_NS";
    EXPECT_EQ( "CNAME",  dns::TypeCodeToString( dns::TYPE_CNAME ) )  << "'CNAME'  -> TYPE_CNAME";
    EXPECT_EQ( "NAPTR",  dns::TypeCodeToString( dns::TYPE_NAPTR ) )  << "'NAPTR'  -> TYPE_NAPTR";
    EXPECT_EQ( "DNAME",  dns::TypeCodeToString( dns::TYPE_DNAME ) )  << "'DNAME'  -> TYPE_DNAME";
    EXPECT_EQ( "MX",     dns::TypeCodeToString( dns::TYPE_MX ) )     << "'MX'     -> TYPE_MX";
    EXPECT_EQ( "TXT",    dns::TypeCodeToString( dns::TYPE_TXT ) )    << "'TXT'    -> TYPE_TXT";
    EXPECT_EQ( "SOA",    dns::TypeCodeToString( dns::TYPE_SOA ) )    << "'SOA'    -> TYPE_SOA";
    EXPECT_EQ( "KEY",    dns::TypeCodeToString( dns::TYPE_KEY ) )    << "'KEY'    -> TYPE_KEY";
    EXPECT_EQ( "AAAA",   dns::TypeCodeToString( dns::TYPE_AAAA ) )   << "'AAAA'   -> TYPE_AAAA";
    EXPECT_EQ( "OPT",    dns::TypeCodeToString( dns::TYPE_OPT ) )    << "'OPT'    -> TYPE_OPT";
    EXPECT_EQ( "DNSKEY", dns::TypeCodeToString( dns::TYPE_DNSKEY ) ) << "'DNSKEY' -> TYPE_DNSKEY";
    EXPECT_EQ( "TSIG",   dns::TypeCodeToString( dns::TYPE_TSIG ) )   << "'TSIG'   -> TYPE_TSIG";
    EXPECT_EQ( "TKEY",   dns::TypeCodeToString( dns::TYPE_TKEY ) )   << "'TKEY'   -> TYPE_TKEY"; 
    EXPECT_EQ( "IXFR",   dns::TypeCodeToString( dns::TYPE_IXFR ) )   << "'IXFR'   -> TYPE_IXFR";
    EXPECT_EQ( "AXFR",   dns::TypeCodeToString( dns::TYPE_AXFR ) )   << "'AXFR'   -> TYPE_AXFR";
    EXPECT_EQ( "ANY",    dns::TypeCodeToString( dns::TYPE_ANY ) )    << "'ANY'    -> TYPE_ANY";
}


class TypeToString : public ::testing::Test
{
public:

};

TEST_F( TypeToString, convert_a_to_type_a )
{
    EXPECT_EQ( dns::TYPE_A,      dns::StringToTypeCode( "A" ) )      << "TYPE_A      -> 'A'";
    EXPECT_EQ( dns::TYPE_NS,     dns::StringToTypeCode( "NS" ) )     << "TYPE_NS     -> 'NS'";
    EXPECT_EQ( dns::TYPE_CNAME,  dns::StringToTypeCode( "CNAME" ) )  << "TYPE_CNAME  -> 'CNAME'";
    EXPECT_EQ( dns::TYPE_NAPTR,  dns::StringToTypeCode( "NAPTR" ) )  << "TYPE_NAPTR  -> 'NAPTR'";
    EXPECT_EQ( dns::TYPE_DNAME,  dns::StringToTypeCode( "DNAME" ) )  << "TYPE_DNAME  -> 'DNAME'";
    EXPECT_EQ( dns::TYPE_MX,     dns::StringToTypeCode( "MX" ) )     << "TYPE_MX     -> 'MX'";
    EXPECT_EQ( dns::TYPE_TXT,    dns::StringToTypeCode( "TXT" ) )    << "TYPE_TXT    -> 'TXT'";
    EXPECT_EQ( dns::TYPE_SOA,    dns::StringToTypeCode( "SOA" ) )    << "TYPE_SOA    -> 'SOA'";
    EXPECT_EQ( dns::TYPE_KEY,    dns::StringToTypeCode( "KEY" ) )    << "TYPE_KEY    -> 'KEY'";
    EXPECT_EQ( dns::TYPE_AAAA,   dns::StringToTypeCode( "AAAA" ) )   << "TYPE_AAAA   -> 'AAAA'";
    EXPECT_EQ( dns::TYPE_OPT,    dns::StringToTypeCode( "OPT" ) )    << "TYPE_OPT    -> 'OPT'";
    EXPECT_EQ( dns::TYPE_DNSKEY, dns::StringToTypeCode( "DNSKEY" ) ) << "TYPE_DNSKEY -> 'DNSKEY'";
    EXPECT_EQ( dns::TYPE_TSIG,   dns::StringToTypeCode( "TSIG" ) )   << "TYPE_TSIG   -> 'TSIG'";
    EXPECT_EQ( dns::TYPE_TKEY,   dns::StringToTypeCode( "TKEY" ) )   << "TYPE_TKEY   -> 'TKEY'"; 
    EXPECT_EQ( dns::TYPE_IXFR,   dns::StringToTypeCode( "IXFR" ) )   << "TYPE_IXFR   -> 'IXFR'";
    EXPECT_EQ( dns::TYPE_AXFR,   dns::StringToTypeCode( "AXFR" ) )   << "TYPE_AXFR   -> 'AXFR'";
    EXPECT_EQ( dns::TYPE_ANY,    dns::StringToTypeCode( "ANY" ) )    << "TYPE_ANY    -> 'ANY'";
}


class ClassifyResponseSuccess : public ::testing::Test
{   
public:
    dns::MessageInfo createHeaderInfo( bool aa, uint8_t rcode )
    {
	dns::MessageInfo message;
    
	message.id                   = 1;
	message.query_response       = 1;
	message.opcode               = 0;
	message.authoritative_answer = aa;
	message.truncation           = false;
	message.recursion_desired    = false;
	message.recursion_available  = false;
	message.checking_disabled    = true;
	message.authentic_data       = 0;
	message.response_code        = rcode;

	return message;
    }
};


TEST_F( ClassifyResponseSuccess, success_response )
{
    dns::MessageInfo response = createHeaderInfo( true, dns::NO_ERROR );
    response.edns0 = false;
    response.tsig  = false;

    dns::QuestionSectionEntry question { "a.dns.jp", dns::TYPE_A, dns::CLASS_IN };
    response.question_section.push_back( question );

    dns::ResponseSectionEntry answer { "a.dns.jp", dns::TYPE_A, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.0.1" ) ) };
    response.answer_section.push_back( answer );

    dns::ResponseSectionEntry ns1 { "dns.jp", dns::TYPE_NS, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordNS( "nsa.dns.jp" ) ) };
    dns::ResponseSectionEntry ns2 { "dns.jp", dns::TYPE_NS, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordNS( "nsb.dns.jp" ) ) };
    response.authority_section.push_back( ns1 );
    response.authority_section.push_back( ns2 );

    dns::ResponseSectionEntry additional1 { "nsa.dns.jp", dns::TYPE_A, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.1.1" ) ) };
    dns::ResponseSectionEntry additional2 { "nsb.dns.jp", dns::TYPE_A, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.1.2" ) ) };
    response.additional_infomation_section.push_back( additional1 );
    response.additional_infomation_section.push_back( additional2 );

    EXPECT_EQ( dns::RESPONSE_SUCCESS, dns::classifyResponse( response ) ) << "response type SUCCESS";
}


TEST_F( ClassifyResponseSuccess, cname_response )
{
    dns::MessageInfo response = createHeaderInfo( true, dns::NO_ERROR );
    response.edns0 = false;
    response.tsig  = false;

    dns::QuestionSectionEntry question { "www.dns.jp", dns::TYPE_A, dns::CLASS_IN };
    response.question_section.push_back( question );

    dns::ResponseSectionEntry answer1  { "www.dns.jp", dns::TYPE_CNAME, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordCNAME( "a.dns.jp" ) ) };
    dns::ResponseSectionEntry answer2  { "a.dns.jp",   dns::TYPE_A,     dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.0.1" ) ) };
    response.answer_section.push_back( answer1 );
    response.answer_section.push_back( answer2 );

    dns::ResponseSectionEntry ns1 { "dns.jp", dns::TYPE_NS, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordNS( "nsa.dns.jp" ) ) };
    dns::ResponseSectionEntry ns2 { "dns.jp", dns::TYPE_NS, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordNS( "nsb.dns.jp" ) ) };
    response.authority_section.push_back( ns1 );
    response.authority_section.push_back( ns2 );

    dns::ResponseSectionEntry additional1 { "nsa.dns.jp", dns::TYPE_A, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.1.1" ) ) };
    dns::ResponseSectionEntry additional2 { "nsb.dns.jp", dns::TYPE_A, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.1.2" ) ) };
    response.additional_infomation_section.push_back( additional1 );
    response.additional_infomation_section.push_back( additional2 );

    EXPECT_EQ( dns::RESPONSE_CNAME, dns::classifyResponse( response ) ) << "response type CNAME";
}


TEST_F( ClassifyResponseSuccess, referral_response )
{
    dns::MessageInfo response = createHeaderInfo( true, dns::NO_ERROR );
    response.edns0 = false;
    response.tsig  = false;

    dns::QuestionSectionEntry question { "a.dns.jp", dns::TYPE_A, dns::CLASS_IN };
    response.question_section.push_back( question );

    dns::ResponseSectionEntry ns1 { "dns.jp", dns::TYPE_NS, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordNS( "nsa.dns.jp" ) ) };
    dns::ResponseSectionEntry ns2 { "dns.jp", dns::TYPE_NS, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordNS( "nsb.dns.jp" ) ) };
    response.authority_section.push_back( ns1 );
    response.authority_section.push_back( ns2 );

    dns::ResponseSectionEntry additional1 { "nsa.dns.jp", dns::TYPE_A, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.1.1" ) ) };
    dns::ResponseSectionEntry additional2 { "nsb.dns.jp", dns::TYPE_A, dns::CLASS_IN, 3600, dns::RDataPtr( new dns::RecordA( "192.168.1.2" ) ) };
    response.additional_infomation_section.push_back( additional1 );
    response.additional_infomation_section.push_back( additional2 );

    EXPECT_EQ( dns::RESPONSE_REFERRAL, dns::classifyResponse( response ) ) << "response type REFERRAL";
}


TEST_F( ClassifyResponseSuccess, nodata_response )
{
    dns::MessageInfo response = createHeaderInfo( true, dns::NO_ERROR );
    response.edns0 = false;
    response.tsig  = false;

    dns::QuestionSectionEntry question { "a.dns.jp", dns::TYPE_A, dns::CLASS_IN };
    response.question_section.push_back( question );

    dns::ResponseSectionEntry soa {
	"dns.jp",
	    dns::TYPE_SOA,
	    dns::CLASS_IN, 3600,
	    dns::RDataPtr( new dns::RecordSOA( "z.dns.jp", "hostmaster.dns.jp", 1, 3600, 2600, 36000, 300 ) ),
	    };
    response.authority_section.push_back( soa );

    EXPECT_EQ( dns::RESPONSE_NODATA, dns::classifyResponse( response ) ) << "response type NODATA";
}

TEST_F( ClassifyResponseSuccess, nxdomain_response )
{
    dns::MessageInfo response = createHeaderInfo( true, dns::NXDOMAIN );
    response.edns0 = false;
    response.tsig  = false;

    dns::QuestionSectionEntry question { "a.dns.jp", dns::TYPE_A, dns::CLASS_IN };
    response.question_section.push_back( question );

    dns::ResponseSectionEntry soa {
	"dns.jp",
	    dns::TYPE_SOA,
	    dns::CLASS_IN, 3600,
	    dns::RDataPtr( new dns::RecordSOA( "z.dns.jp", "hostmaster.dns.jp", 1, 3600, 2600, 36000, 300 ) ),
	    };
    response.authority_section.push_back( soa );

    EXPECT_EQ( dns::RESPONSE_NXDOMAIN, dns::classifyResponse( response ) ) << "response type NXDOMAIN";
}


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
