#include "connection.h"
#include "compressor.h"
#include "src/util/fatal_assert.h"

using namespace Network;

Connection::Connection( const char* key_str,
                        const char* ip,
                        const char* udp_port,
                        const char* tcp_port,
                        NetworkTransportMode mode )
{
  switch ( mode ) {
    case NetworkTransportMode::TCP_ONLY:
      tcp_connection.emplace( key_str, ip, tcp_port );
      break;
    case NetworkTransportMode::UDP_ONLY:
      udp_connection.emplace( key_str, ip, udp_port );
      break;
    default:
      throw NetworkException( "Invalid transport mode" );
  }
}

Connection::Connection( const char* desired_ip,
                        const char* desired_udp_port,
                        const char* desired_tcp_port,
                        NetworkTransportMode mode )
{
  switch ( mode ) {
    case NetworkTransportMode::TCP_ONLY:
      tcp_connection.emplace( desired_ip, desired_tcp_port );
      break;
    case NetworkTransportMode::UDP_ONLY:
      udp_connection.emplace( desired_ip, desired_udp_port );
      break;
    default:
      throw NetworkException( "Invalid transport mode" );
  }
}

bool Connection::parse_portrange( const char* desired_port, int& desired_port_low, int& desired_port_high )
{
  /* parse "udp_port" or "portlow:porthigh" */
  desired_port_low = desired_port_high = 0;
  char* end;
  long value;

  /* parse first (only?) udp_port */
  errno = 0;
  value = strtol( desired_port, &end, 10 );
  if ( ( errno != 0 ) || ( *end != '\0' && *end != ':' ) ) {
    fprintf( stderr, "Invalid (low) udp_port number (%s)\n", desired_port );
    return false;
  }
  if ( ( value < 0 ) || ( value > 65535 ) ) {
    fprintf( stderr, "(Low) port number %ld outside valid range [0..65535]\n", value );
    return false;
  }

  desired_port_low = (int)value;
  if ( *end == '\0' ) { /* not a udp_port range */
    desired_port_high = desired_port_low;
    return true;
  }
  /* port range; parse high udp_port */
  const char* cp = end + 1;
  errno = 0;
  value = strtol( cp, &end, 10 );
  if ( ( errno != 0 ) || ( *end != '\0' ) ) {
    fprintf( stderr, "Invalid high udp_port number (%s)\n", cp );
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

void Connection::udp_send_in_fragments( const Instruction& inst, bool verbose, int send_interval )
{
  std::vector<Fragment> fragments = fragmenter.make_fragments(
    inst, udp_connection->get_MTU() - Network::UDPConnection::ADDED_BYTES - Crypto::Session::ADDED_BYTES );
  for ( auto& fragment : fragments ) {
    udp_connection->send( fragment.tostring() );

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
        (int)udp_connection->timeout(),
        udp_connection->get_SRTT() );
    }
  }
}

void Connection::tcp_send( const Instruction& inst, bool verbose, int send_interval )
{
  std::string msg = get_compressor().compress_str( inst.SerializeAsString() );
  tcp_connection->send( msg );
  if ( verbose ) {
    fprintf( stderr,
             "[%u] Sent [%d=>%d] TCP ack=%d, throwaway=%d, len=%d, frame rate=%.2f, timeout=%d, srtt=%.1f\n",
             (unsigned int)( timestamp() % 100000 ),
             (int)inst.old_num(),
             (int)inst.new_num(),
             (int)inst.ack_num(),
             (int)inst.throwaway_num(),
             (int)msg.size(),
             1000.0 / send_interval,
             (int)udp_connection->timeout(),
             udp_connection->get_SRTT() );
  }
}

void Connection::send_instruction( const Instruction& inst, bool verbose, int send_interval )
{
  last_ack_sent = inst.ack_num();
  if ( udp_connection.has_value() ) {
    udp_send_in_fragments( inst, verbose, send_interval );
  } else {
    tcp_send( inst, verbose, send_interval );
  }
}

std::optional<Instruction> Connection::udp_recv_from_fragments( void )
{
  std::string s( udp_connection->recv() );
  Fragment frag( s );

  if ( fragments.add_fragment( frag ) ) { /* complete packet */
    return fragments.get_assembly();
  }
  return std::nullopt;
}

std::optional<Instruction> Connection::tcp_recv( void )
{
  std::string msg = tcp_connection->recv();
  if ( msg.empty() ) {
    return std::nullopt;
  }

  Instruction inst;
  fatal_assert( inst.ParseFromString( get_compressor().uncompress_str( msg ) ) );

  return inst;
}

std::optional<Instruction> Connection::recv_instruction( void )
{
  if ( udp_connection.has_value() ) {
    return udp_recv_from_fragments();
  } else {
    return tcp_recv();
  }
}

const std::vector<int> Connection::fds( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->fds();
  } else {
    return tcp_connection->fds();
  }
}

std::string Connection::udp_port( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->port();
  } else {
    return {};
  }
}

std::string Connection::tcp_port( void ) const
{
  if ( tcp_connection.has_value() ) {
    return tcp_connection->port();
  } else {
    return {};
  }
}

std::string Connection::get_key( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->get_key();
  } else {
    return tcp_connection->get_key();
  }
}

bool Connection::get_has_remote_addr( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->get_has_remote_addr();
  } else {
    return tcp_connection->get_has_remote_addr();
  }
}

uint64_t Connection::timeout( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->timeout();
  } else {
    return tcp_connection->timeout();
  }
}

double Connection::get_SRTT( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->get_SRTT();
  } else {
    return tcp_connection->get_SRTT();
  }
}

const Addr& Connection::get_remote_addr( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->get_remote_addr();
  } else {
    return tcp_connection->get_remote_addr();
  }
}

socklen_t Connection::get_remote_addr_len( void ) const
{
  if ( udp_connection.has_value() ) {
    return udp_connection->get_remote_addr_len();
  } else {
    return tcp_connection->get_remote_addr_len();
  }
}

std::string& Connection::get_send_error( void )
{
  if ( udp_connection.has_value() ) {
    return udp_connection->get_send_error();
  } else {
    return tcp_connection->get_send_error();
  }
}

void Connection::set_last_roundtrip_success( uint64_t s_success )
{
  if ( udp_connection.has_value() ) {
    return udp_connection->set_last_roundtrip_success( s_success );
  }
}
