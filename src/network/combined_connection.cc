#include "combined_connection.h"
#include "compressor.h"
#include "src/util/fatal_assert.h"

using namespace Network;

CombinedConnection::CombinedConnection( Base64Key key, const char* addr, Port udp_port, Port tcp_port )
  : is_server( false ), udp_connection( key, addr, udp_port ), tcp_connection( key, addr, tcp_port ),
    active_connection( &udp_connection )
{}

CombinedConnection::CombinedConnection( Base64Key key,
                                        const char* desired_ip,
                                        PortRange desired_udp_port,
                                        PortRange desired_tcp_port )
  : is_server( true ), udp_connection( key, desired_ip, desired_udp_port ),
    tcp_connection( key, desired_ip, desired_tcp_port ), active_connection( &udp_connection )
{}

void CombinedConnection::switch_to_tcp()
{
  if ( report_fn ) {
    report_fn( TransportChangedReport {
      transport,
      Transport::TCP,
    } );
  }
  udp_recv_count = 0;
  tcp_recv_count = 0;
  active_connection = &tcp_connection;
  transport = Transport::TCP;
  mode_switched_timestamp = timestamp();
}

void CombinedConnection::switch_to_udp()
{
  if ( report_fn ) {
    report_fn( TransportChangedReport {
      transport,
      Transport::UDP,
    } );
  }
  udp_recv_count = 0;
  tcp_recv_count = 0;
  active_connection = &udp_connection;
  transport = Transport::UDP;
  mode_switched_timestamp = timestamp();
}

bool CombinedConnection::should_probe_udp()
{
  const auto timeout
    = std::clamp( (uint64_t)( 20 * udp_connection.get_SRTT() ), (uint64_t)10'000, (uint64_t)15'000 );
  return ( timestamp() - last_roundtrip_success_timestamp > timeout )
         || timestamp() - last_udp_send_timestamp >= UDP_PROBE_TIMEOUT_MS;
}

bool CombinedConnection::should_probe_tcp()
{
  const auto timeout
    = std::clamp( (uint64_t)( 20 * udp_connection.get_SRTT() ), (uint64_t)10'000, (uint64_t)15'000 );
  return timestamp() - last_roundtrip_success_timestamp > timeout;
}

void CombinedConnection::send( const TransportBuffers::Instruction& inst )
{
  if ( transport == Transport::UDP || transport == Transport::BOTH ) {
    udp_connection.send( inst );
    last_udp_send_timestamp = timestamp();
  }

  if ( transport == Transport::TCP || transport == Transport::BOTH ) {
    tcp_connection.send( inst );
    last_tcp_send_timestamp = timestamp();
  }
}

void CombinedConnection::set_report_function( Connection::ReportFunction report_fn )
{
  tcp_connection.set_report_function( report_fn );
  udp_connection.set_report_function( std::move( report_fn ) );
}

std::optional<TransportBuffers::Instruction> CombinedConnection::recv( void )
{
  std::optional<TransportBuffers::Instruction> tcp_inst;
  std::optional<TransportBuffers::Instruction> udp_inst;

  if ( ( tcp_inst = tcp_connection.recv() ) ) {
    last_tcp_recv_timestamp = timestamp();
    tcp_recv_count++;
  }

  if ( ( udp_inst = udp_connection.recv() ) ) {
    last_udp_recv_timestamp = timestamp();
    udp_recv_count++;
  }

  // The other side is attempting to use a different protocol also respond back on that protocol
  if ( transport == Transport::TCP && udp_inst ) {
    if ( report_fn ) {
      report_fn( TransportChangedReport { transport, Transport::BOTH } );
    }
    transport = Transport::BOTH;
  } else if ( transport == Transport::UDP && tcp_inst ) {
    if ( report_fn ) {
      report_fn( TransportChangedReport { transport, Transport::BOTH } );
    }
    transport = Transport::BOTH;
  }

  if ( !is_server && transport == Transport::UDP ) {
    assert( !tcp_connection.is_enabled() );
  }

  if ( tcp_inst && udp_inst ) {
    return tcp_inst->new_num() > udp_inst->new_num() && tcp_inst->old_num() <= udp_inst->old_num() ? tcp_inst
                                                                                                   : udp_inst;
  } else if ( udp_inst ) {
    return udp_inst;
  }
  return tcp_inst;
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
  return udp_connection.has_remote_addr() || tcp_connection.has_remote_addr();
}

uint64_t CombinedConnection::get_RTO( void ) const
{
  if ( transport == Transport::BOTH ) {
    return std::min( udp_connection.get_RTO(), tcp_connection.get_RTO() );
  } else {
    return active_connection->get_RTO();
  }
}

double CombinedConnection::get_SRTT( void ) const
{
  if ( transport == Transport::BOTH ) {
    return std::min( udp_connection.get_SRTT(), tcp_connection.get_SRTT() );
  } else {
    return active_connection->get_SRTT();
  }
}

const Addr* CombinedConnection::get_remote_addr( void ) const
{
  return active_connection->get_remote_addr();
}

void CombinedConnection::set_last_roundtrip_success( uint64_t timestamp )
{
  last_roundtrip_success_timestamp = timestamp;
  active_connection->set_last_roundtrip_success( timestamp );
}

std::string CombinedConnection::clear_send_error( void )
{
  std::string tcp_error = tcp_connection.clear_send_error();
  std::string udp_error = udp_connection.clear_send_error();
  return transport == Transport::TCP ? tcp_error : udp_error;
}

void CombinedConnection::register_select( Select& select )
{
  if ( verbose ) {
    fprintf( stderr,
             "MODE:%s probe_udp:%d, probe_tcp:%d, udp_recv_count:%lu, tcp_recv_count:%lu, last_roundrip:%lu, "
             "last_udp_recv:%lu, last_tcp_recv:%lu\n",
             transport_name( transport ),
             should_probe_udp(),
             should_probe_tcp(),
             udp_recv_count,
             tcp_recv_count,
             timestamp() - last_roundtrip_success_timestamp,
             timestamp() - last_udp_recv_timestamp,
             timestamp() - last_tcp_recv_timestamp );
  }

  // The client decides to probe/send on a different connection. The server may switch the protocols when receiving
  if ( !is_server ) {
    if ( transport == Transport::UDP && should_probe_tcp() ) {
      if ( report_fn ) {
        report_fn( TransportChangedReport {
          transport,
          Transport::BOTH,
        } );
      }
      transport = Transport::BOTH;
      tcp_connection.enable();
      udp_recv_count = 0;
      tcp_recv_count = 0;
      mode_switched_timestamp = timestamp();
    } else if ( transport == Transport::TCP && should_probe_udp() ) {
      if ( report_fn ) {
        report_fn( TransportChangedReport {
          transport,
          Transport::BOTH,
        } );
      }
      transport = Transport::BOTH;
      udp_recv_count = 0;
      tcp_recv_count = 0;
      mode_switched_timestamp = timestamp();
    }
  }

  // See if we want to switch to only a single protocol, but only do so if we have successfully transmitted
  if ( transport == Transport::BOTH && timestamp() - last_roundtrip_success_timestamp < 5'000
       && timestamp() - mode_switched_timestamp > 5'000 ) {
    if ( udp_recv_count >= 3 ) {
      if ( !is_server ) {
        tcp_connection.disable();
        assert( !tcp_connection.is_enabled() );
      }
      switch_to_udp();
    } else if ( tcp_recv_count >= 10 ) {
      switch_to_tcp();
    }
  }

  if ( is_server || transport == Transport::BOTH || transport == Transport::UDP ) {
    udp_connection.register_select( select );
  }

  if ( is_server || transport == Transport::BOTH || transport == Transport::TCP ) {
    tcp_connection.register_select( select );
  }
}

Actions CombinedConnection::wakeup( Select& select )
{
  if ( is_server || transport == Transport::BOTH ) {
    Actions tcp_actions = tcp_connection.wakeup( select );
    Actions udp_actions = udp_connection.wakeup( select );
    return Actions { tcp_actions.recv || udp_actions.recv };
  } else if ( transport == Transport::TCP ) {
    return tcp_connection.wakeup( select );
  }
  return udp_connection.wakeup( select );
}
