#ifndef UTILS_HPP
#define UTILS_HPP

#include <arpa/inet.h>
#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <cerrno>
#include <stdexcept>
#include <vector>

typedef std::vector<uint8_t> PacketData;

struct ClientParameters {
    std::string address;
    uint16_t    port;
};


/*!
 * IPアドレスのテキスト形式をバイナリ形式(in_addr)へ変換できない場合にthrowする例外
 */
class InvalidAddressFormatError : public std::runtime_error
{
public:
    InvalidAddressFormatError( const std::string &msg ) : std::runtime_error( msg )
    {
    }
};

/*!
 * ヘッダに記載されているpayloadの長さが、不正な場合にthrowする例外
 */
class InvalidPayloadLengthError : public std::runtime_error
{
private:
    int length;

public:
    InvalidPayloadLengthError( const std::string &msg, int len ) : std::runtime_error( msg ), length( len )
    {
    }

    int payload_length() const
    {
        return length;
    }
};

/*!
 * Socketの操作に失敗した場合にthrowする例外
 */
class SocketError : public std::runtime_error
{
public:
    SocketError( const std::string &msg ) : std::runtime_error( msg )
    {
    }
};

std::string get_error_message( const std::string &msg, int error_number );

std::string toLower( const std::string &str );
std::string toUpper( const std::string &str );

in_addr convertAddressStringToBinary( const std::string &str );
std::string convertAddressBinaryToString( in_addr bin );


char *encode_to_base64( const uint8_t *begin, const uint8_t *end, char *output );
void encode_to_base64( const std::vector<uint8_t> &, std::string & );

uint8_t *decode_from_base64( const char *begin, const char *end, uint8_t *output );
uint8_t *decode_from_base64( const char *data, uint8_t *output );
void decode_from_base64( const std::string &, std::vector<uint8_t> & );

uint32_t encode_to_base64_size( const uint8_t *begin, const uint8_t *end );
uint32_t decode_from_base64_size( const char *begin, const char *end );

void md5( const uint8_t *d, uint32_t size, uint8_t result[ 16 ] );

std::string printPacketData( const PacketData &p );



#endif
