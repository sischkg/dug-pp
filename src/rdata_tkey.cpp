#include "rdata_tkey.hpp"

namespace dns
{
    uint16_t RecordTKey::size() const
    {
        return algorithm.size() + //
               4 +                // inception
               4 +                // expiration
               2 +                // mode
               2 +                // error
               2 +                // key size
               key.size() +       // key
               2 +                // other data size
               other_data.size();
    }

    void RecordTKey::outputWireFormat( WireFormat &message ) const
    {
        algorithm.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( inception );
        message.pushUInt32HtoN( expiration );
        message.pushUInt16HtoN( mode );
        message.pushUInt16HtoN( error );
        message.pushUInt16HtoN( key.size() );
        message.pushBuffer( key );
        message.pushUInt16HtoN( other_data.size() );
        message.pushBuffer( other_data );
    }
}

