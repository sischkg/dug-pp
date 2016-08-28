#include "utils.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class ToLowerCaseTest : public ::testing::Test
{
public:
};

TEST_F( ToLowerCaseTest, upper_to_lower )
{
    EXPECT_EQ( "abcxyz", toLower( "ABCXYZ" ) ) << "ABCXYZ -> abcxyz";
}

TEST_F( ToLowerCaseTest, lower_to_lower )
{
    EXPECT_EQ( "abcxyz", toLower( "abcxyz" ) ) << "abcxyz -> abcxyz";
}

TEST_F( ToLowerCaseTest, include_digit_lower )
{
    EXPECT_EQ( "abc123xyz", toLower( "ABC123XYZ" ) ) << "ABC123XYZ -> abc123xyz";
}


class ToUpperCaseTest : public ::testing::Test
{
public:
};

TEST_F( ToUpperCaseTest, lower_to_upper )
{
    EXPECT_EQ( "ABCXYZ", toUpper( "abcxyz" ) ) << "abcxyz -> ABCXYZ";
}

TEST_F( ToUpperCaseTest, upper_to_upper )
{
    EXPECT_EQ( "ABCXYZ", toUpper( "ABCXYZ" ) ) << "ABCXYZ -> ABCXYZ";
}

TEST_F( ToUpperCaseTest, include_digit_upper )
{
    EXPECT_EQ( "ABC123XYZ", toUpper( "abc123xyz" ) ) << "abc123xyz -> ABC123XYZ";
}


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
