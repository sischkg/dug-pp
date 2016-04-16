#include "rdata_optpseudo.hpp"
#include <sstream>
#include <cstring>

namespace dns
{
    std::string RecordOptionsData::toString() const
    {
        std::ostringstream os;

        for ( auto i = options.begin(); i != options.end(); ++i )
            os << ( *i )->toString();

        return os.str();
    }

    uint16_t RecordOptionsData::size() const
    {
        uint16_t rr_size = 0;
        for ( auto i = options.begin(); i != options.end(); i++ ) {
            rr_size += ( *i )->size();
        }
        return rr_size;
    }

    void RecordOptionsData::outputWireFormat( WireFormat &message ) const
    {
        for ( auto i = options.begin(); i != options.end(); i++ ) {
            ( *i )->outputWireFormat( message );
        }
    }

    RDataPtr RecordOptionsData::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos = begin;

        std::vector<OptPseudoRROptPtr> options;
        while ( pos < end ) {
            if ( end - pos < 4 ) {
                std::ostringstream os;
                os << "remains data " << end - pos << " is too few size.";
                throw FormatError( os.str() );
            }
            uint16_t option_code = ntohs( get_bytes<uint16_t>( &pos ) );
            uint16_t option_size = ntohs( get_bytes<uint16_t>( &pos ) );

            if ( option_size == 0 )
                continue;
            if ( pos + option_size > end ) {
                std::ostringstream os;
                os << "option data size is missmatch: option_size: " << option_size << "; remain size " << end - pos;
                throw FormatError( os.str() );
            }

            switch ( option_code ) {
            case OPT_NSID:
                options.push_back( NSIDOption::parse( pos, pos + option_size ) );
                break;
            default:
                break;
            }
            pos += option_size;
        }

        return RDataPtr( new RecordOptionsData( options ) );
    }

    void NSIDOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_NSID );
        message.pushUInt16HtoN( nsid.size() );
        message.pushBuffer( reinterpret_cast<const uint8_t *>( nsid.c_str() ),
                            reinterpret_cast<const uint8_t *>( nsid.c_str() ) + nsid.size() );
    }

    OptPseudoRROptPtr NSIDOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        std::string nsid( begin, end );
        return OptPseudoRROptPtr( new NSIDOption( nsid ) );
    }

    unsigned int ClientSubnetOption::getAddressSize( uint8_t prefix )
    {
        return ( prefix + 7 ) / 8;
    }

    void ClientSubnetOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_CLIENT_SUBNET );
        message.pushUInt16HtoN( size() );
        message.pushUInt16HtoN( family );
        message.pushUInt8( source_prefix );
        message.pushUInt8( scope_prefix );

        if ( family == IPv4 ) {
            uint8_t addr_buf[ 4 ];
            inet_pton( AF_INET, address.c_str(), addr_buf );
            message.pushBuffer( addr_buf, addr_buf + getAddressSize( source_prefix ) );
        } else {
            uint8_t addr_buf[ 16 ];
            inet_pton( AF_INET6, address.c_str(), addr_buf );
            message.pushBuffer( addr_buf, addr_buf + getAddressSize( source_prefix ) );
        }
    }

    uint16_t ClientSubnetOption::size() const
    {
        return 2 + 1 + 1 + getAddressSize( source_prefix ) + 4;
    }

    std::string ClientSubnetOption::toString() const
    {
        std::ostringstream os;
        os << "EDNSClientSubnet: "
           << "source:  " << (int)source_prefix << "scope:   " << (int)scope_prefix << "address: " << address;
        return os.str();
    }

    OptPseudoRROptPtr ClientSubnetOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos = begin;

        uint16_t fam    = ntohs( get_bytes<uint16_t>( &pos ) );
        uint8_t  source = get_bytes<uint8_t>( &pos );
        uint8_t  scope  = get_bytes<uint8_t>( &pos );

        if ( fam == IPv4 ) {
            if ( source > 32 ) {
                throw FormatError( "invalid source prefix length of EDNS-Client-Subet" );
            }
            if ( scope > 32 ) {
                throw FormatError( "invalid scope prefix length of EDNS-Client-Subet" );
            }

            if ( source == 0 )
                return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, "0.0.0.0" ) );

            uint8_t addr_buf[ 4 ];
            char    addr_str[ INET_ADDRSTRLEN ];

            std::memset( addr_buf, 0, sizeof( addr_buf ) );
            std::memset( addr_str, 0, sizeof( addr_str ) );

            std::memcpy( addr_buf, pos, getAddressSize( source ) );
            inet_ntop( AF_INET, addr_buf, addr_str, sizeof( addr_buf ) );

            return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, addr_str ) );
        } else if ( fam == IPv6 ) {
            if ( source > 32 ) {
                throw FormatError( "invalid source prefix length of EDNS-Client-Subet" );
            }
            if ( scope > 32 ) {
                throw FormatError( "invalid scope prefix length of EDNS-Client-Subet" );
            }

            if ( source == 0 )
                return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, "::0" ) );

            uint8_t addr_buf[ 16 ];
            char    addr_str[ INET6_ADDRSTRLEN ];

            std::memset( addr_buf, 0, sizeof( addr_buf ) );
            std::memset( addr_str, 0, sizeof( addr_str ) );

            std::memcpy( addr_buf, pos, getAddressSize( source ) );
            inet_ntop( AF_INET6, addr_buf, addr_str, sizeof( addr_buf ) );

            return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, addr_str ) );
        } else {
            throw FormatError( "invalid family of EDNS-Client-Subet" );
        }
    }
}
