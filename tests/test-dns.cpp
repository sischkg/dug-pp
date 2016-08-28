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


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
