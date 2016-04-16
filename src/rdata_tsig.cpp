#include "rdata_tsig.hpp"
#include "dns.hpp"
#include <openssl/hmac.h>
#include <sstream>

namespace dns
{
    uint16_t RecordTSIG::size() const
    {
        return algorithm.size() + // ALGORITHM
	    6 +                // signed time
	    2 +                // FUDGE
	    2 +                // MAC SIZE
	    mac.size() +       // MAC
	    2 +                // ORIGINAL ID
	    2 +                // ERROR
	    2 +                // OTHER LENGTH
	    other.size();      // OTHER
    }

    void RecordTSIG::outputWireFormat( WireFormat &message ) const
    {
        uint32_t time_high = signed_time >> 16;
        uint32_t time_low  = ( ( 0xffff & signed_time ) << 16 ) + fudge;

        algorithm.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( time_high );
        message.pushUInt32HtoN( time_low );
        message.pushUInt16HtoN( mac_size );
        message.pushBuffer( mac );
        message.pushUInt16HtoN( original_id );
        message.pushUInt16HtoN( error );
        message.pushUInt16HtoN( other_length );
        message.pushBuffer( other );
    }

    std::string RecordTSIG::toString() const
    {
        std::ostringstream os;
        os << "key name: " << key_name << ", "
           << "algorigthm: " << algorithm << ", "
           << "signed time: " << signed_time << ", "
           << "fudge: " << fudge << ", "
           << "MAC: " << printPacketData( mac ) << ", "
           << "Original ID: " << original_id << ", "
           << "Error: " << error;

        return os.str();
    }

    RDataPtr
    RecordTSIG::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end, const Domainname &key_name )
    {
        const uint8_t *pos = begin;

        Domainname algorithm;
        pos = Domainname::parsePacket( algorithm, packet, pos );
        if ( pos >= end )
            throw FormatError( "too short message for TSIG RR" );

        uint64_t time_high = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t time_low  = ntohl( get_bytes<uint32_t>( &pos ) );
        if ( pos >= end )
            throw FormatError( "too short message for TSIG RR" );
        uint64_t signed_time = ( time_high << 16 ) + ( time_low >> 16 );
        uint16_t fudge       = time_low;

        uint16_t mac_size = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos + mac_size >= end )
            throw FormatError( "too short message for TSIG RR" );
        PacketData mac;
        mac.insert( mac.end(), pos, pos + mac_size );
        pos += mac_size;

        uint16_t original_id = ntohs( get_bytes<uint16_t>( &pos ) );
        uint16_t error       = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos >= end )
            throw FormatError( "too short message for TSIG RR" );

        uint16_t other_length = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos + other_length > end )
            throw FormatError( "too short message for TSIG RR" );
        PacketData other;
        other.insert( other.end(), pos, pos + other_length );
        pos += other_length;

        return RDataPtr( new RecordTSIG( key_name.toString(),
					 algorithm.toString(),
					 signed_time,
					 fudge,
					 mac_size,
					 mac,
					 original_id,
					 error,
					 other_length,
					 other ) );
    }

    struct TSIGHash {
        Domainname name;
        Domainname algorithm;
        uint64_t   signed_time;
        uint16_t   fudge;
        uint16_t   error;
        uint16_t   other_length;
        PacketData other;

        PacketData getPacket() const;
        uint16_t   size() const;
    };

    uint16_t TSIGHash::size() const
    {
        return name.size() + 2 + 4 + algorithm.size() + 6 + 2 + 2 + 2 + other.size();
    }

    PacketData TSIGHash::getPacket() const
    {
        PacketData packet;
        packet.resize( size() );

        PacketData name_data      = name.getCanonicalWireFormat();
        PacketData algorithm_data = algorithm.getCanonicalWireFormat();

        uint32_t time_high = signed_time >> 16;
        uint32_t time_low  = ( ( 0xffff & signed_time ) << 16 ) + fudge;

        uint8_t *pos = &packet[ 0 ];
        pos          = std::copy( name_data.begin(), name_data.end(), pos );
        pos          = set_bytes<uint16_t>( htons( CLASS_ANY ), pos );
        pos          = set_bytes<uint32_t>( htonl( 0 ), pos );
        pos          = std::copy( algorithm_data.begin(), algorithm_data.end(), pos );
        pos          = set_bytes<uint32_t>( htonl( time_high ), pos );
        pos          = set_bytes<uint32_t>( htonl( time_low ), pos );
        pos          = set_bytes<uint16_t>( htons( error ), pos );
        pos          = set_bytes<uint16_t>( htons( other_length ), pos );
        pos          = std::copy( other.begin(), other.end(), pos );

        return packet;
    }


    PacketData getTSIGMAC( const TSIGInfo &tsig_info, const PacketData &message, const PacketData &query_mac )
    {
        PacketData   mac( EVP_MAX_MD_SIZE );
        unsigned int mac_size = EVP_MAX_MD_SIZE;

        PacketData hash_data = query_mac;

        PacketData         presigned_message = message;
        PacketHeaderField *h                 = reinterpret_cast<PacketHeaderField *>( &presigned_message[ 0 ] );
        h->id                                = htons( tsig_info.original_id );
        hash_data.insert( hash_data.end(), presigned_message.begin(), presigned_message.end() );

        TSIGHash tsig_hash;
        tsig_hash.name            = tsig_info.name;
        tsig_hash.algorithm       = tsig_info.algorithm;
        tsig_hash.signed_time     = tsig_info.signed_time;
        tsig_hash.fudge           = tsig_info.fudge;
        tsig_hash.error           = tsig_info.error;
        tsig_hash.other_length    = tsig_info.other.size();
        tsig_hash.other           = tsig_info.other;
        PacketData tsig_hash_data = tsig_hash.getPacket();

        hash_data.insert( hash_data.end(), tsig_hash_data.begin(), tsig_hash_data.end() );

        OpenSSL_add_all_digests();
        HMAC( EVP_get_digestbyname( "md5" ),
              &tsig_info.key[ 0 ],
              tsig_info.key.size(),
              reinterpret_cast<const unsigned char *>( &hash_data[ 0 ] ),
              hash_data.size(),
              reinterpret_cast<unsigned char *>( &mac[ 0 ] ),
              &mac_size );
        EVP_cleanup();
        mac.resize( mac_size );

        return mac;
    }


    void addTSIGResourceRecord( const TSIGInfo &tsig_info, WireFormat &message, const PacketData &query_mac )
    {
        PacketData mac = getTSIGMAC( tsig_info, message.get(), query_mac );

        ResponseSectionEntry entry;
        entry.domainname = tsig_info.name;
        entry.type       = TYPE_TSIG;
        entry.klass      = CLASS_ANY;
        entry.ttl        = 0;
        entry.rdata      = RDataPtr( new RecordTSIG( tsig_info.name,
						     tsig_info.algorithm,
						     tsig_info.signed_time,
						     tsig_info.fudge,
						     mac.size(),
						     mac,
						     tsig_info.original_id,
						     tsig_info.error,
						     tsig_info.other.size(),
						     tsig_info.other ) );
        PacketData         packet  = message.get();
        PacketHeaderField *header  = reinterpret_cast<PacketHeaderField *>( &packet[ 0 ] );
        uint16_t           adcount = ntohs( header->additional_infomation_count );
        adcount++;
        header->additional_infomation_count = htons( adcount );

	WireFormat tsig_wireformat;
	generate_response_section( entry, tsig_wireformat );
        PacketData tsig_packet = tsig_wireformat.get();
 
        packet.insert( packet.end(), tsig_packet.begin(), tsig_packet.end() );

        message.clear();
        message.pushBuffer( packet );
    }

    bool verifyTSIGResourceRecord( const TSIGInfo &tsig_info, const MessageInfo &packet_info, const WireFormat &message )
    {
        PacketData hash_data = message.get();

        PacketHeaderField *header = reinterpret_cast<PacketHeaderField *>( &hash_data[ 0 ] );
        header->id                = htons( tsig_info.original_id );
        uint16_t adcount          = ntohs( header->additional_infomation_count );
        if ( adcount < 1 ) {
            throw FormatError( "adcount of message with TSIG record must not be 0" );
        }
        header->additional_infomation_count = htons( adcount - 1 );

        const uint8_t *pos = &hash_data[ 0 ];
        pos += sizeof( PacketHeaderField );

        // skip question section
        for ( uint16_t i = 0; i < packet_info.question_section.size(); i++ )
            pos = parse_question_section( &hash_data[ 0 ], pos ).second;

        // skip answer section
        for ( uint16_t i = 0; i < packet_info.answer_section.size(); i++ )
            pos = parse_response_section( &hash_data[ 0 ], pos ).second;

        // skip authority section
        for ( uint16_t i = 0; i < packet_info.authority_section.size(); i++ )
            pos = parse_response_section( &hash_data[ 0 ], pos ).second;

        // skip non TSIG Record in additional section
        bool is_found_tsig = false;
        for ( uint16_t i = 0; i < packet_info.additional_infomation_section.size(); i++ ) {
            ResponseSectionEntryPair parsed_rr_pair = parse_response_section( &hash_data[ 0 ], pos );
            if ( parsed_rr_pair.first.type == TYPE_TSIG ) {
                is_found_tsig = true;
                break;
            } else {
                pos = parsed_rr_pair.second;
            }
        }

        if ( !is_found_tsig ) {
            throw FormatError( "not found tsig record" );
        }
        // remove TSIG RR( TSIG must be final RR in message )
        hash_data.resize( pos - &hash_data[ 0 ] );

        PacketData mac = getTSIGMAC( tsig_info, hash_data, PacketData() );

        if ( mac.size() != tsig_info.mac_size )
            return false;

        for ( unsigned int i = 0; mac.size(); i++ ) {
            if ( mac[ i ] != tsig_info.mac[ i ] )
                return false;
        }

        return true;
    }
}

