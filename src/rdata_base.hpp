#ifndef RDATA_BASE_HPP
#define RDATA_BASE_HPP

#include "dns_base.hpp"

namespace dns
{
    class RData
    {
    public:
        virtual ~RData()
        {
        }

        virtual std::string toString() const                              = 0;
        virtual void        outputWireFormat( WireFormat &message ) const = 0;
        virtual Type        type() const                                  = 0;
        virtual uint16_t    size() const                                  = 0;
        virtual RData      *clone() const                                 = 0;
    };

    typedef std::shared_ptr<RData> RDataPtr;

    class RecordRaw : public RData
    {
    private:
        uint16_t             rrtype;
        std::vector<uint8_t> data;

    public:
        RecordRaw( uint8_t t, const std::vector<uint8_t> &d )
	    : rrtype( t ), data( d )
        {
        }

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual Type type() const
        {
            return rrtype;
        }
        virtual uint16_t size() const
        {
            return data.size();
        }
	virtual RecordRaw* clone() const
	{
	    return new RecordRaw( rrtype, data );
	}
    };

}

#endif
