#include "rdata_txt.hpp"
#include <sstream>

namespace dns
{
    RecordTXT::RecordTXT( const std::string &d )
    {
        data.push_back( d );
    }

    RecordTXT::RecordTXT( const std::vector<std::string> &d ) 
	: data( d )
    {}

    std::string RecordTXT::toString() const
    {
        std::ostringstream os;
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            os << "\"" << data[ i ] << "\" ";
        }

        return os.str();
    }

    void RecordTXT::outputWireFormat( WireFormat &message ) const
    {
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            message.push_back( data[ i ].size() & 0xff );
            for ( unsigned int j = 0; j < data[ i ].size(); j++ )
                message.push_back( data[ i ][ j ] );
        }
    }

    uint16_t RecordTXT::size() const
    {
        uint16_t s = 0;
        for ( auto i = data.begin(); i != data.end(); i++ ) {
            s++;
            s += i->size();
        }
        return s;
    }

    RDataPtr RecordTXT::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin < 1 )
            throw FormatError( "too few length for TXT record" );
        const uint8_t *          pos = begin;
        std::vector<std::string> txt_data;

        while ( pos < end ) {
            uint8_t length = get_bytes<uint8_t>( &pos );
            if ( pos + length > end )
                throw FormatError( "bad charactor-code length" );
            txt_data.push_back( std::string( pos, pos + length ) );
            pos += length;
        }
        return RDataPtr( new RecordTXT( txt_data ) );
    }
}
