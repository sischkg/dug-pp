#ifndef WIREFORMAT_HPP
#define WIREFORMAT_HPP

#include <arpa/inet.h>
#include <boost/cstdint.hpp>
#include <iostream>
#include <stdexcept>
#include <vector>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include "utils.hpp"
#include <endian.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef std::vector<uint8_t> PacketData;

class WireFormat
{
private:
    uint16_t               mBufferSize;
    uint16_t               mEnd;
    std::vector<uint8_t *> mBuffers;

    void checkIndex( uint16_t i ) const throw( std::runtime_error )
    {
        if ( i >= mEnd )
            throw std::runtime_error( "range error" );
    }

public:
    WireFormat( uint16_t buffer_size = 512 );
    WireFormat( const std::vector<uint8_t> &data, uint16_t buffer_size = 512 );
    WireFormat( const uint8_t *begin, const uint8_t *end, uint16_t buffer_size = 512 );

    ~WireFormat();

    void push_back( uint8_t v )
    {
        if ( mEnd % mBufferSize == 0 )
            mBuffers.push_back( new uint8_t[ mBufferSize ] );

        *( mBuffers.back() + mEnd % mBufferSize ) = v;
        mEnd++;
    }

    uint8_t pop_back() throw( std::runtime_error )
    {
        if ( mEnd == 0 )
            throw std::runtime_error( "cannot pop_back because buffer is emptry." );
        uint8_t ret = ( *this )[ mEnd - 1 ];
        mEnd--;
        return ret;
    }

    void clear();

    void pushUInt8( uint8_t v )
    {
        push_back( v );
    }

    void pushUInt16( uint16_t v )
    {
        push_back( ( uint8_t )( 0xff & ( v >> 0 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 8 ) ) );
    }

    void pushUInt32( uint32_t v )
    {
        push_back( ( uint8_t )( 0xff & ( v >> 0 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 8 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 16 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 24 ) ) );
    }

    void pushUInt64( uint64_t v )
    {
        push_back( ( uint8_t )( 0xff & ( v >> 0 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 8 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 16 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 24 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 32 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 40 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 48 ) ) );
        push_back( ( uint8_t )( 0xff & ( v >> 56 ) ) );
    }

    void pushUInt16HtoN( uint16_t v )
    {
        pushUInt16( htons( v ) );
    }
    void pushUInt32HtoN( uint32_t v )
    {
        pushUInt32( htonl( v ) );
    }
    void pushUInt64HtoN( uint64_t v )
    {
        pushUInt64( htobe64( v ) );
    }

    void pushBuffer( const uint8_t *begin, const uint8_t *end )
    {
        for ( ; begin != end; begin++ )
            push_back( *begin );
    }

    void pushBuffer( const PacketData &data )
    {
        pushBuffer( &data[ 0 ], &data[ 0 ] + data.size() );
    }

    const uint8_t &operator[]( uint16_t i ) const throw( std::runtime_error )
    {
        checkIndex( i );

        return mBuffers[ i / mBufferSize ][ i % mBufferSize ];
    }

    uint8_t &operator[]( uint16_t i ) throw( std::runtime_error )
    {
        checkIndex( i );

        return mBuffers[ i / mBufferSize ][ i % mBufferSize ];
    }

    const uint8_t &at( uint16_t i ) const throw( std::runtime_error )
    {
        return ( *this )[ i ];
    }

    uint16_t size() const
    {
        return mEnd;
    }

    template <class UnaryFunction>
    void foreach ( UnaryFunction func ) const
    {
        for ( uint16_t i = 0; i < size(); i++ ) {
            func( at( i ) );
        }
    }

    uint16_t send( int fd, const sockaddr *dest, socklen_t dest_length, int flags = 0 ) const
        throw( std::runtime_error );
    PacketData get() const;

    struct MessageHeader {
        msghdr header;

        MessageHeader();
        ~MessageHeader();

        void setBuffers( uint16_t size, const std::vector<uint8_t *>, uint16_t buffer_size );
        void setDestination( const sockaddr *dest, uint16_t len );
    };
};

#endif
