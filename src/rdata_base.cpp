#include "rdata_base.hpp"
#include <sstream>

namespace dns
{
    std::string RecordRaw::toString() const
    {
        std::ostringstream os;
        os << "type: " << rrtype << ", data: ";
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            os << std::hex << (unsigned int)data[ i ] << " ";
        }
        return os.str();
    }

    void RecordRaw::outputWireFormat( WireFormat &message ) const
    {
        message.pushBuffer( data );
    }
}

