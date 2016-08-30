#include <iostream>
#include <boost/program_options.hpp>
#include "udpv4client.hpp"
#include "dns.hpp"

namespace po = boost::program_options;

int main( int argc, char **argv )
{
    std::string target_server, arg_qname, arg_qtype;
    bool is_recursive = false;

    po::options_description desc( "DNS Client" );
    desc.add_options()
	( "help,h",
	  "print this message" )

        ( "server,s",
          po::value<std::string>( &target_server ),
          "target dns server address" )

	( "name,n",
	  po::value<std::string>( &arg_qname ),
	  "qname" )

	( "type,t",
	  po::value<std::string>( &arg_qtype ),
	  "qtype" )

	( "recursive,r",
	  "recursive query" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 0;
    }
    if ( vm.count( "recursive" ) )
	is_recursive = true;

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
    message_info.recursion_desired    = is_recursive ? 1 : 0;
    message_info.recursion_available  = 0;
    message_info.zero_field           = 0;
    message_info.authentic_data       = 0;
    message_info.checking_disabled    = 1;
    message_info.response_code        = 0;

    
    std::cout << "==== Query ====" << std::endl << message_info << std::endl;
    
    WireFormat query_message;
    dns::generateDNSMessage( message_info, query_message );

    ClientParameters udp_param;
    udp_param.address = target_server;
    udp_param.port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( query_message );

    udpv4::PacketInfo response_message = udp.receivePacket();
    dns::MessageInfo res = dns::parseDNSMessage( response_message.begin(), response_message.end() );

    std::cout << "==== Response ====" << std::endl << res;

    return 0;
}
