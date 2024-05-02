#ifndef MOSH_CONNECTION_H
#define MOSH_CONNECTION_H

#include "udp_connection.h"

namespace Network {

class Connection
{
  UDPConnection udp_connection;

public:
  static bool parse_portrange( const char* desired_port_range, int& desired_port_low, int& desired_port_high );

  Connection( const char* key_str, const char* ip, const char* port );

  Connection( const char* desired_ip, const char* desired_port );

  void send( const std::string& s );
  std::string recv( void );
  const std::vector<int> fds( void ) const;
  int get_MTU( void ) const;

  std::string port( void ) const;
  std::string get_key( void ) const;
  bool get_has_remote_addr( void ) const;

  uint64_t timeout( void ) const;
  double get_SRTT( void ) const;

  const Addr& get_remote_addr( void ) const;
  socklen_t get_remote_addr_len( void ) const;

  std::string& get_send_error( void );

  void set_last_roundtrip_success( uint64_t s_success );
};
}

#endif // MOSH_CONNECTION_H