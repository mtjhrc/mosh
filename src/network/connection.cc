#include "connection.h"

using namespace Network;

bool Connection::parse_portrange( const char* desired_port, int& desired_port_low, int& desired_port_high )
{
  /* parse "port" or "portlow:porthigh" */
  desired_port_low = desired_port_high = 0;
  char* end;
  long value;

  /* parse first (only?) port */
  errno = 0;
  value = strtol( desired_port, &end, 10 );
  if ( ( errno != 0 ) || ( *end != '\0' && *end != ':' ) ) {
    fprintf( stderr, "Invalid (low) port number (%s)\n", desired_port );
    return false;
  }
  if ( ( value < 0 ) || ( value > 65535 ) ) {
    fprintf( stderr, "(Low) port number %ld outside valid range [0..65535]\n", value );
    return false;
  }

  desired_port_low = (int)value;
  if ( *end == '\0' ) { /* not a port range */
    desired_port_high = desired_port_low;
    return true;
  }
  /* port range; parse high port */
  const char* cp = end + 1;
  errno = 0;
  value = strtol( cp, &end, 10 );
  if ( ( errno != 0 ) || ( *end != '\0' ) ) {
    fprintf( stderr, "Invalid high port number (%s)\n", cp );
    return false;
  }
  if ( ( value < 0 ) || ( value > 65535 ) ) {
    fprintf( stderr, "High port number %ld outside valid range [0..65535]\n", value );
    return false;
  }

  desired_port_high = (int)value;
  if ( desired_port_low > desired_port_high ) {
    fprintf( stderr, "Low port %d greater than high port %d\n", desired_port_low, desired_port_high );
    return false;
  }

  if ( desired_port_low == 0 ) {
    fprintf( stderr, "Low port 0 incompatible with port ranges\n" );
    return false;
  }

  return true;
}

Connection::Connection( const char* key_str, const char* ip, const char* port )
  : udp_connection( key_str, ip, port )
{}

Connection::Connection( const char* desired_ip, const char* desired_port )
  : udp_connection( desired_ip, desired_port )
{}

void Connection::udp_send_in_fragments( const Instruction& inst, bool verbose, int send_interval )
{
  std::vector<Fragment> fragments = fragmenter.make_fragments(
    inst, udp_connection.get_MTU() - Network::UDPConnection::ADDED_BYTES - Crypto::Session::ADDED_BYTES );
  for ( auto& fragment : fragments ) {
    udp_connection.send( fragment.tostring() );

    if ( verbose ) {
      fprintf(
        stderr,
        "[%u] Sent [%d=>%d] id %d, frag %d ack=%d, throwaway=%d, len=%d, frame rate=%.2f, timeout=%d, srtt=%.1f\n",
        (unsigned int)( timestamp() % 100000 ),
        (int)inst.old_num(),
        (int)inst.new_num(),
        (int)fragment.id,
        (int)fragment.fragment_num,
        (int)inst.ack_num(),
        (int)inst.throwaway_num(),
        (int)fragment.contents.size(),
        1000.0 / send_interval,
        (int)udp_connection.timeout(),
        udp_connection.get_SRTT() );
    }
  }
}

void Connection::send_instruction( const Instruction& inst, bool verbose, int send_interval )
{
  last_ack_sent = inst.ack_num();
  udp_send_in_fragments( inst, verbose, send_interval );
}

std::optional<Instruction> Connection::udp_recv_from_fragments( void )
{
  std::string s( udp_connection.recv() );
  Fragment frag( s );

  if ( fragments.add_fragment( frag ) ) { /* complete packet */
    return fragments.get_assembly();
  }
  return std::nullopt;
}

std::optional<Instruction> Connection::recv_instruction( void )
{
  return udp_recv_from_fragments();
}

const std::vector<int> Connection::fds( void ) const
{
  return udp_connection.fds();
}

std::string Connection::port( void ) const
{
  return udp_connection.port();
}

std::string Connection::get_key( void ) const
{
  return udp_connection.get_key();
}

bool Connection::get_has_remote_addr( void ) const
{
  return udp_connection.get_has_remote_addr();
}

uint64_t Connection::timeout( void ) const
{
  return udp_connection.timeout();
}

double Connection::get_SRTT( void ) const
{
  return udp_connection.get_SRTT();
}

const Addr& Connection::get_remote_addr( void ) const
{
  return udp_connection.get_remote_addr();
}

socklen_t Connection::get_remote_addr_len( void ) const
{
  return udp_connection.get_remote_addr_len();
}

std::string& Connection::get_send_error( void )
{
  return udp_connection.get_send_error();
}

void Connection::set_last_roundtrip_success( uint64_t s_success )
{
  return udp_connection.set_last_roundtrip_success( s_success );
}
