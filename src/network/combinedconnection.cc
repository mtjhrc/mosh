#include "combinedconnection.h"
#include "compressor.h"
#include "src/util/fatal_assert.h"

using namespace Network;

CombinedConnection::CombinedConnection( Base64Key key, const char* addr, Port udp_port, Port tcp_port )
  : udp_connection( key, addr, udp_port ), tcp_connection( key, addr, tcp_port ),
    active_connection( &udp_connection )
{}

CombinedConnection::CombinedConnection( Base64Key key,
                                        const char* desired_ip,
                                        PortRange desired_udp_port,
                                        PortRange desired_tcp_port )
  : udp_connection( key, desired_ip, desired_udp_port ), tcp_connection( key, desired_ip, desired_tcp_port ),
    active_connection( &udp_connection )
{}

void CombinedConnection::switch_to_tcp() {
  active_connection = &tcp_connection;
  using_udp = false;
}

void CombinedConnection::switch_to_udp() {
  active_connection = &udp_connection;
  using_udp = true;
}

bool CombinedConnection::should_probe_udp()
{
  return timestamp() - last_tcp_recv_timestamp > tcp_connection.timeout()
         || timestamp() - last_udp_send_timestamp >= UDP_PROBE_TIMEOUT_MS;
}

bool CombinedConnection::should_probe_tcp()
{
  // This also returns true for initial state of `last_udp_recv_timestamp` being 0, that is intended
  // because we may need to fall back to TCP right away
  return timestamp() - last_udp_recv_timestamp > udp_connection.timeout();
}

void CombinedConnection::send( const Instruction& inst )
{
  if (using_udp || should_probe_udp()) {
    udp_connection.send( inst );
    last_udp_send_timestamp = timestamp();
  }

  if (!using_udp || should_probe_tcp()) {
    tcp_connection.send( inst );
  }
}

void CombinedConnection::set_report_function( Connection::ReportFunction report_fn )
{
  tcp_connection.set_report_function( report_fn );
  udp_connection.set_report_function( std::move( report_fn ) );
}

std::optional<Instruction> CombinedConnection::recv( void )
{
  std::optional<Instruction> inst = udp_connection.recv();
  if ( inst ) {
    last_udp_recv_timestamp = timestamp();
    switch_to_udp();
    return inst;
  }
  inst = tcp_connection.recv();
  if ( inst ) {
    last_tcp_recv_timestamp = timestamp();
    switch_to_tcp();
  }
  return inst;
}

std::vector<int> CombinedConnection::fds_notify_read( void ) const
{
  std::vector<int> fds = udp_connection.fds_notify_read();
  auto tcp_fds = tcp_connection.fds_notify_read();
  fds.insert( fds.end(), tcp_fds.begin(), tcp_fds.end() );
  return fds;
}

std::vector<int> CombinedConnection::fds_notify_write( void ) const
{
  return tcp_connection.fds_notify_write();
}

bool CombinedConnection::finish_send( void )
{
  return tcp_connection.finish_send();
}

std::optional<Port> CombinedConnection::udp_port() const
{
  return udp_connection.udp_port();
}

std::optional<Port> CombinedConnection::tcp_port( void ) const
{
  return tcp_connection.tcp_port();
}

bool CombinedConnection::has_remote_addr( void ) const
{
  return active_connection->has_remote_addr();
}

uint64_t CombinedConnection::timeout( void ) const
{
  return std::min( udp_connection.timeout(), tcp_connection.timeout() );
}

double CombinedConnection::get_SRTT( void ) const
{
  return active_connection->get_SRTT();
}

const Addr* CombinedConnection::get_remote_addr( void ) const
{
  return active_connection->get_remote_addr();
}

std::string CombinedConnection::clear_send_error( void )
{
  std::string tcp_error = tcp_connection.clear_send_error();
  std::string udp_error = udp_connection.clear_send_error();
  return using_udp ? tcp_error : udp_error;
}

void CombinedConnection::set_last_roundtrip_success( uint64_t timestamp )
{
  active_connection->set_last_roundtrip_success( timestamp );
}
