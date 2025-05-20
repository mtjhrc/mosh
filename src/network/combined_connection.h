#ifndef MOSH_COMBINED_CONNECTION_H
#define MOSH_COMBINED_CONNECTION_H

#include <optional>

#include "connection.h"
#include "network.h"
#include "src/protobufs/transportinstruction.pb.h"
#include "tcp_connection.h"
#include "transportfragment.h"
#include "udp_connection.h"

namespace Network {

class CombinedConnection : public Connection
{
  bool verbose = false;
  bool is_server;

  UDPConnection udp_connection;
  TCPConnection tcp_connection;
  Connection* active_connection;
  Transport transport = Transport::BOTH;
  std::function<void()> init_tcp_connection;
  Connection::ReportFunction report_fn;
  uint64_t last_roundtrip_success_timestamp = 0;

  uint64_t last_udp_recv_timestamp = 0;
  uint64_t last_tcp_recv_timestamp = 0;
  uint64_t last_udp_send_timestamp = 0;
  uint64_t last_tcp_send_timestamp = 0;
  uint64_t udp_recv_count = 0;
  uint64_t tcp_recv_count = 0;
  uint64_t mode_switched_timestamp = 0;

  const uint64_t UDP_PROBE_TIMEOUT_MS = 10'000;

  void switch_to_tcp();
  void switch_to_udp();
  bool should_probe_tcp();
  bool should_probe_udp();

public:
  CombinedConnection( const CombinedConnection& ) = delete;
  CombinedConnection( CombinedConnection&& ) = delete;
  CombinedConnection& operator=( CombinedConnection&& ) = delete;
  CombinedConnection& operator=( const CombinedConnection& ) = delete;

  CombinedConnection( Base64Key key,
                      const char* desired_ip,
                      PortRange desired_udp_port,
                      PortRange desired_tcp_port );

  CombinedConnection( Base64Key key, const char* ip, Port udp_port, Port tcp_port );

  void set_report_function( Connection::ReportFunction report_fn ) override;

  void send( const Instruction& inst ) override;
  std::string clear_send_error( void ) override;

  std::optional<Instruction> recv( void ) override;

  virtual void register_select( Select& select ) override;

  virtual Actions wakeup( Select& select ) override;

  std::optional<Port> udp_port( void ) const override;
  std::optional<Port> tcp_port( void ) const override;

  uint64_t get_RTO( void ) const override;
  double get_SRTT( void ) const override;

  const Addr* get_remote_addr( void ) const override;
  bool has_remote_addr( void ) const override;

  void set_last_roundtrip_success( uint64_t timestamp ) override;

  void set_verbose( bool s_verbose ) override { verbose = s_verbose; };
};
}

#endif // MOSH_COMBINED_CONNECTION_H