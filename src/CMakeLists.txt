add_library( libdns
  utils.cpp
  wireformat.cpp
  udpv4client.cpp
  tcpv4client.cpp
  domainname.cpp
  dns.cpp
  rdata_base.cpp
  rdata_a.cpp
  rdata_aaaa.cpp
  rdata_apl.cpp
  rdata_cname.cpp
  rdata_dname.cpp
  rdata_dnskey.cpp
  rdata_mx.cpp
  rdata_naptr.cpp
  rdata_ns.cpp
  rdata_optpseudo.cpp
  rdata_soa.cpp
  rdata_tkey.cpp
  rdata_tsig.cpp
  rdata_txt.cpp
  )

add_executable( dugpp        dugpp.cpp )
target_link_libraries( dugpp boost_program_options libdns crypto)

add_executable( dugpp-trace  dugpp-trace.cpp )
target_link_libraries( dugpp-trace boost_program_options libdns crypto)

