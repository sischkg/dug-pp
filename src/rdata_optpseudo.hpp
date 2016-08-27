#ifndef RDATA_OPT_PSEUDO_HPP
#define RDATA_OPT_PSEUDO_HPP

#include "rdata_base.hpp"

namespace dns
{
    class OptPseudoRROption
    {
    public:
        virtual ~OptPseudoRROption()
        {
        }
        virtual std::string toString() const                       = 0;
        virtual void        outputWireFormat( WireFormat & ) const = 0;
        virtual uint16_t    code() const                           = 0;
        virtual uint16_t    size() const                           = 0;
    };

    typedef boost::shared_ptr<OptPseudoRROption> OptPseudoRROptPtr;

    class RAWOption : public OptPseudoRROption
    {
    private:
        uint16_t             option_code;
        uint16_t             option_size;
        std::vector<uint8_t> option_data;

    public:
        RAWOption( uint16_t in_code, uint16_t in_size, const std::vector<uint8_t> &in_data )
            : option_code( in_code ), option_size( in_size ), option_data( in_data )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return option_code;
        }
        virtual uint16_t size() const
        {
            return option_size;
        }
    };

    class NSIDOption : public OptPseudoRROption
    {
    private:
        std::string nsid;

    public:
        NSIDOption( const std::string &id = "" ) : nsid( id )
        {
        }

        virtual std::string toString() const
        {
            return "NSID: \"" + nsid + "\"";
        }
        virtual void     outputWireFormat( WireFormat & ) const;
        virtual uint16_t code() const
        {
            return OPT_NSID;
        }
        virtual uint16_t size() const
        {
            return 2 + 2 + nsid.size();
        }

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class ClientSubnetOption : public OptPseudoRROption
    {
    private:
        uint16_t    family;
        uint8_t     source_prefix;
        uint8_t     scope_prefix;
        std::string address;

        static unsigned int getAddressSize( uint8_t prefix );

    public:
        static const int IPv4 = 1;
        static const int IPv6 = 2;

        ClientSubnetOption( uint16_t fam, uint8_t source, uint8_t scope, const std::string &addr )
            : family( fam ), source_prefix( source ), scope_prefix( scope ), address( addr )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_CLIENT_SUBNET;
        }
        virtual uint16_t size() const;

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class RecordOptionsData : public RData
    {
    public:
        std::vector<OptPseudoRROptPtr> options;

    public:
        RecordOptionsData( const std::vector<OptPseudoRROptPtr> &in_options = std::vector<OptPseudoRROptPtr>() )
            : options( in_options )
        {
        }

        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_OPT;
        }
        virtual uint16_t size() const;

        const std::vector<OptPseudoRROptPtr> &getOptions() const
        {
            return options;
        }
        static RDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };

    struct OptPseudoRecord {
        uint16_t                 payload_size;
        uint8_t                  rcode;
        boost::shared_ptr<RData> record_options_data;
	
        OptPseudoRecord( uint16_t size = 0,
			 uint8_t  code = 0,
			 boost::shared_ptr<RData> rdata = boost::shared_ptr<RData>() )
	    : payload_size( size ),
	      rcode( code ),
	      record_options_data( rdata )
        {
        }

	void outputWireFormat( WireFormat & ) const;
    };
}

#endif
