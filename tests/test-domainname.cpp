#include "domainname.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>


class ParseDomainname : public ::testing::Test
{};

TEST_F( ParseDomainname, parse )
{
    dns::Domainname name( "a.dns.jp" );
    const std::deque<std::string> &labels = name.getLabels();
    EXPECT_EQ( "a",   labels[0] ) << "labels[0] of a.dns.jp is 'a'";
    EXPECT_EQ( "dns", labels[1] ) << "labels[1] of a.dns.jp is 'dns'";
    EXPECT_EQ( "jp",  labels[2] ) << "labels[2] of a.dns.jp is 'jp'";
}


class LowerCase : public ::testing::Test
{};

TEST_F( LowerCase, lower_case )
{
    dns::Domainname name( "a.DNS.JP" );
    const std::deque<std::string> &labels = name.getLowerCaseLabels();
    EXPECT_EQ( "a",   labels[0] ) << "labels[0] of a.dns.jp is 'a'";
    EXPECT_EQ( "dns", labels[1] ) << "labels[1] of a.DNS.JP is 'dns'";
    EXPECT_EQ( "jp",  labels[2] ) << "labels[2] of a.DNS.JP is 'jp'";
}


class TestIsInternalName : public ::testing::Test
{
public:

};

TEST_F( TestIsInternalName, is_internal_lowercase )
{
    dns::Domainname parent( "dns.jp" ), child( "a.dns.jp" );
    EXPECT_TRUE( parent.isInternalName( child ) ) << "a.dns.jp is a internal name of dns.jp";
}

TEST_F( TestIsInternalName, is_internal_upper_case )
{
    dns::Domainname parent( "DNS.JP" ), child( "A.DNS.JP" );
    EXPECT_TRUE( parent.isInternalName( child ) ) << "A.DNS.JP is a internal name of DNS.JP";
}

TEST_F( TestIsInternalName, is_internal_parent_lower_child_upper_case )
{
    dns::Domainname parent( "dns.jp" ), child( "A.DNS.JP" );
    EXPECT_TRUE( parent.isInternalName( child ) ) << "A.DNS.JP is a internal name of dns.jp";
}

TEST_F( TestIsInternalName, is_internal_parent_upper_child_lower_case )
{
    dns::Domainname parent( "DNS.JP" ), child( "a.dns.jp" );
    EXPECT_TRUE( parent.isInternalName( child ) ) << "a.dns.jp is a internal name of DNS.JP";
}


class TestIsNotInternalName : public ::testing::Test
{
public:

};

TEST_F( TestIsNotInternalName, is_not_internal )
{
    dns::Domainname parent( "dns.org" ), child( "a.dns.jp" );
    EXPECT_FALSE( parent.isInternalName( child ) ) << "a.dns.jp is not a internal name of dns.org";
}

TEST_F( TestIsNotInternalName, is_not_internal_2 )
{
    dns::Domainname parent( "ldap.jp" ), child( "a.dns.jp" );
    EXPECT_FALSE( parent.isInternalName( child ) ) << "a.dns.jp is not a internal name of ldap.jp";
}


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
