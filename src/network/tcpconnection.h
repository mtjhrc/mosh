#ifndef MOSH_TCPCONNECTION_H
#define MOSH_TCPCONNECTION_H

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

#include "../crypto/crypto.h"
#include "../protobufs/transportinstruction.pb.h"
#include "network.h"
#include "udp_connection.h"
#include <initializer_list>

namespace Network {

class TCPConnection : public Connection
{
private:
  using packet_len_t = uint32_t;
  static const packet_len_t MAX_PACKET_LEN = UINT32_MAX;

  static const uint64_t MIN_RTO = 50;   /* ms */
  static const uint64_t MAX_RTO = 1000; /* ms */

  ReportFunction report_fn;

  std::optional<Socket> server_socket;
  std::optional<Socket> sock;

  bool connection_established = false;

  Addr remote_addr;

  Base64Key key;
  Session session;

  Direction direction;
  uint16_t saved_timestamp;
  uint64_t saved_timestamp_received_at;
  uint64_t expected_receiver_seq = 0;

  bool RTT_hit = false;
  double SRTT = 1000;
  double RTTVAR = 500;

  packet_len_t rcv_current_packet_len = 0;
  packet_len_t rcv_index = 0;
  std::string rcv_buf;

  std::string send_buffer;
  std::string::size_type send_buffer_index = 0;

  bool fill_rcv_buf( ssize_t size );

  /* Error from send()/sendto(). */
  std::string send_error;

  Packet new_packet( const std::string& s_payload );

  bool is_server() const { return server_socket.has_value(); }
  void set_connection_established( bool connection_established );

  bool establish_connection( void );

  std::optional<packet_len_t> send_bytes(const std::string& data, packet_len_t index);
  void send_dropped(const TransportBuffers::Instruction& inst);

public:
  TCPConnection( Crypto::Base64Key key, const char* desired_ip, PortRange desired_udp_port );
  TCPConnection( Crypto::Base64Key key, const char* addr, Port port );

  void set_report_function( ReportFunction report_fn ) override { this->report_fn = std::move( report_fn ); }

  void send( const TransportBuffers::Instruction& inst ) override;
  std::string clear_send_error( void ) override;
  bool finish_send( void ) override;

  std::optional<Instruction> recv( void ) override;

  std::vector<int> fds_notify_read() const override
  {
    std::vector<int> fds;

    if ( server_socket.has_value() ) {
      fds.push_back( server_socket->fd() );
    }

    if ( sock.has_value() ) {
      fds.push_back( sock->fd() );
    }

    return fds;
  };

  std::vector<int> fds_notify_write( void ) const override
  {
    if ( !send_buffer.empty() ) {
      return std::vector<int> { sock.value().fd() };
    }
    return {};
  }

  std::optional<Port> udp_port( void ) const override { return std::nullopt; };
  std::optional<Port> tcp_port( void ) const override;

  void set_last_roundtrip_success( uint64_t timestamp ) override
  {
    // TCP connection doesn't need this
  }

  uint64_t timeout( void ) const override;
  double get_SRTT( void ) const override { return SRTT; }

  const Addr* get_remote_addr( void ) const override { return connection_established ? &remote_addr : nullptr; }
  bool has_remote_addr( void ) const override { return connection_established; }
};

}
#endif