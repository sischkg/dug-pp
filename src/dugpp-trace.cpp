#include <iostream>
#include <boost/program_options.hpp>
#include "udpv4client.hpp"
#include "dns.hpp"

namespace po = boost::program_options;

const char *DEFAULT_ROOT_SERVER = "198.41.0.4"; // a.root-servers.net


void iterate_query( const dns::Domainname &qname, dns::Type type, dns::ResponseSectionEntry &result )
{

}


int main( int argc, char **argv )
{
    std::string arg_qname, arg_qtype, arg_root_server;

    po::options_description desc( "DNS Client" );
    desc.add_options()
	( "help,h",
	  "print this message" )

	( "name,n",
	  po::value<std::string>( &arg_qname ),
	  "qname" )

	( "type,t",
	  po::value<std::string>( &arg_qtype ),
	  "qtype" )

	( "root,r",
	  po::value<std::string>( &arg_root_server )->default_value( DEFAULT_ROOT_SERVER ),
	  "root-server IP address" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 0;
    }


    dns::MessageInfo message_info;

    dns::QuestionSectionEntry question;
    question.domainname = arg_qname;
    question.type       = dns::StringToTypeCode( arg_qtype );
    question.klass      = dns::CLASS_IN;
    message_info.question_section.push_back( question );

    message_info.id                   = 1234;
    message_info.opcode               = 0;
    message_info.query_response       = 0;
    message_info.authoritative_answer = 0;
    message_info.truncation           = 0;
    message_info.recursion_desired    = 0;
    message_info.recursion_available  = 0;
    message_info.zero_field           = 0;
    message_info.authentic_data       = 0;
    message_info.checking_disabled    = 1;
    message_info.response_code        = 0;

    
    std::cout << "==== Query ====" << std::endl << message_info << std::endl;
    
    WireFormat query_message;
    dns::generateDNSMessage( message_info, query_message );

    ClientParameters udp_param;
    udp_param.address = arg_root_server;
    udp_param.port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( query_message );

    udpv4::PacketInfo response_message = udp.receivePacket();
    dns::MessageInfo res = dns::parseDNSMessage( response_message.begin(), response_message.end() );

    std::cout << "==== Response ====" << std::endl << res << std::endl;
    std::cerr << "Response Type: " << dns::ResponseTypeString( dns::classifyResponse( res ) ) << std::endl;

    return 0;
}
