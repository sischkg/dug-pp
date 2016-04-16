#ifndef DOMAINNAME_HPP
#define DOMAINNAME_HPP

#include <deque>
#include <string>
#include "wireformat.hpp"

namespace dns
{
    typedef uint16_t Offset;
    const Offset     NO_COMPRESSION = 0xffff;

    class Domainname
    {
    private:
        std::deque<std::string> labels;

    public:
        Domainname( const std::deque<std::string> &l = std::deque<std::string>() ) : labels( l )
        {}

        Domainname( const std::string &name );
        Domainname( const char *name );

        std::string toString() const;
        void        outputWireFormat( WireFormat & ) const;
        void        outputCanonicalWireFormat( WireFormat & ) const;
        PacketData  getCanonicalWireFormat() const;
        unsigned int size() const;
        const std::deque<std::string> &getLabels() const
        {
            return labels;
        }

        Domainname  operator+( const Domainname & ) const;
        Domainname &operator+=( const Domainname & );
        void        addSubdomain( const std::string & );
        void        addSuffix( const std::string & );

        static const uint8_t *parsePacket( Domainname &   ref_domainname,
                                           const uint8_t *packet,
                                           const uint8_t *begin,
                                           int            recur = 0 );
    };

    std::ostream &operator<<( const Domainname &name, std::ostream &os );
    std::ostream &operator<<( std::ostream &os, const Domainname &name );
    bool operator==( const Domainname &lhs, const Domainname &rhs );
    bool operator!=( const Domainname &lhs, const Domainname &rhs );

    const uint8_t *
    parseCharacterString( const uint8_t *begin, const uint8_t *packet_end, std::string &ref_output );

}

#endif
