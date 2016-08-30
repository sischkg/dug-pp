#include "domainname.hpp"
#include "dns_base.hpp"
#include "cstring"
#include <iostream>

namespace dns
{
    static void stringToLabels( const char *name, std::deque<std::string> &labels )
    {
	labels.clear();

	if ( name == NULL || name[ 0 ] == 0 )
	    return;

        unsigned int name_length = std::strlen( name );
        std::string  label;
        for ( unsigned int i = 0; i < name_length; i++ ) {
            if ( name[ i ] == '.' ) {
		labels.push_back( label );
                label = "";
            } else {
                label.push_back( name[ i ] );
	    }
        }
        if ( label != "" )
            labels.push_back( label );
    }

    static uint8_t toLower( uint8_t c )
    {
        if ( 'A' <= c && c <= 'Z' ) {
            return 'a' + c - 'A';
        }
        return c;
    }

    const uint8_t *
    parseCharacterString( const uint8_t *begin, const uint8_t *packet_end, std::string &ref_output )
    {
        if ( begin == NULL || packet_end == NULL )
            throw std::logic_error( "begin, packet end must not be NULL" );
        if ( begin == packet_end )
            throw FormatError( "character-string length >= 1" );

        const uint8_t *pos  = begin;
        uint8_t        size = get_bytes<uint8_t>( &pos );

        if ( pos + size > packet_end )
            throw FormatError( "character-string size is too long than end of packet" );

        ref_output.assign( reinterpret_cast<const char *>( pos ), size );
        pos += size;
        return pos;
    }

    Domainname::Domainname( const char *name )
    {
        stringToLabels( name, labels );
    }

    Domainname::Domainname( const std::string &name )
    {
        stringToLabels( name.c_str(), labels );
    }

    std::string Domainname::toString() const
    {
        std::string result;
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            result += labels[ i ];
            result += ".";
        }
        return result;
    }

    void Domainname::outputWireFormat( WireFormat &message ) const
    {
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            message.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                message.push_back( labels[ i ][ j ] );
	}

	message.push_back( 0 );
    }

    void Domainname::outputCanonicalWireFormat( WireFormat &message ) const
    {
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            message.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                message.push_back( toLower( labels[ i ][ j ] ) );
        }
        message.push_back( 0 );
    }

    PacketData Domainname::getCanonicalWireFormat() const
    {
	WireFormat wireformat;
	outputCanonicalWireFormat( wireformat );
	return wireformat.get();
    }

    std::deque<std::string> Domainname::getLowerCaseLabels() const
    {
	std::deque<std::string> lower_labels;
	for ( auto &label : labels )
	    lower_labels.push_back( ::toLower( label ) );
	return lower_labels;
    }
    
    bool Domainname::isInternalName( const Domainname &ns_name ) const
    {
	std::deque<std::string> parent = getLowerCaseLabels();
	std::deque<std::string> ns     = ns_name.getLowerCaseLabels();

	if ( parent.size() >= ns.size() )
	    return false;

	auto p = parent.rbegin();
	auto n = ns.rbegin();
	for ( ; p != parent.rend() ; p++, n++  ) {
	    if ( *p != *n )
		return false;
	}

	return true;
    }
	
    
    const uint8_t *Domainname::parsePacket( Domainname &   ref_domainname,
                                            const uint8_t *packet,
                                            const uint8_t *begin,
                                            int            recur )
    {
        if ( recur > 100 ) {
            throw FormatError( "detected domainname decompress loop" );
        }

        std::string    label;
        const uint8_t *p = begin;
        while ( *p != 0 ) {
            // メッセージ圧縮を行っている場合
            if ( *p & 0xC0 ) {
                int offset = ntohs( *( reinterpret_cast<const uint16_t *>( p ) ) ) & 0x0bff;
                if ( packet + offset > begin - 2 ) {
                    throw FormatError( "detected forword reference of domainname decompress..." );
                }

                parsePacket( ref_domainname, packet, packet + offset, recur + 1 );
                return p + 2;
            }

            uint8_t label_length = *p;
            p++;
            for ( uint8_t i = 0; i < label_length; i++, p++ ) {
                label.push_back( *p );
            }
            ref_domainname.addSuffix( label );
            label = "";
        }

        p++;
        return p;
    }

    unsigned int Domainname::size() const
    {
	unsigned int size = 0;
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
	    size++;   // label length = 1byte
	    size += labels[i].size();
	}
	size++;       // "."
        return size;
    }

    Domainname Domainname::operator+( const Domainname &rhs ) const
    {
        Domainname new_domainname = *this;
        new_domainname += rhs;
        return new_domainname;
    }

    Domainname &Domainname::operator+=( const Domainname &rhs )
    {
        labels.insert( labels.end(), rhs.getLabels().begin(), rhs.getLabels().end() );
        return *this;
    }

    void Domainname::addSubdomain( const std::string &label )
    {
        labels.push_front( label );
    }

    void Domainname::addSuffix( const std::string &label )
    {
        labels.push_back( label );
    }

    std::ostream &operator<<( const Domainname &name, std::ostream &os )
    {
        return os << name.toString();
    }

    std::ostream &operator<<( std::ostream &os, const Domainname &name )
    {
        return os << name.toString();
    }

    bool operator==( const Domainname &lhs, const Domainname &rhs )
    {
        if ( lhs.getLabels().size() != rhs.getLabels().size() )
            return false;

        for ( unsigned int i = 0; i < lhs.getLabels().size(); i++ ) {
            const std::string &lhs_label = lhs.getLabels().at( i );
            const std::string &rhs_label = rhs.getLabels().at( i );

            if ( lhs_label.size() != rhs_label.size() )
                return false;

            for ( unsigned int j = 0; j < lhs_label.size(); j++ ) {
                if ( toLower( lhs_label[ j ] ) != toLower( rhs_label[ j ] ) )
                    return false;
            }
        }
        return true;
    }

    bool operator!=( const Domainname &lhs, const Domainname &rhs )
    {
        return !( lhs == rhs );
    }
}
