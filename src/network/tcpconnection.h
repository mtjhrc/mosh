#ifndef MOSH_TCPCONNECTION_H
#define MOSH_TCPCONNECTION_H

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <string>
#include <vector>
#include <optional>

#include <netinet/in.h>
#include <sys/socket.h>

#include "network.h"
#include "src/crypto/crypto.h"
#include "udp_connection.h"

namespace Network {

class TCPConnection
{
private:
  using packet_len_t = uint32_t;

  /* Application datagram MTU. For constructors and fallback. */
  static const int DEFAULT_SEND_MTU = 500;

  static const uint64_t MIN_RTO = 50;   /* ms */
  static const uint64_t MAX_RTO = 1000; /* ms */

  std::optional<Socket> server_socket;
  std::optional<Socket> sock = std::nullopt;

  bool connection_established = false;

  Addr remote_addr;
  socklen_t remote_addr_len;

  Base64Key key;
  Session session;

  Direction direction;
  uint16_t saved_timestamp;
  uint64_t saved_timestamp_received_at;
  uint64_t expected_receiver_seq;

  bool RTT_hit = false;
  double SRTT = 1000;
  double RTTVAR = 500;

  packet_len_t rcv_current_packet_len = 0;
  packet_len_t rcv_index = 0;
  std::string rcv_buf;

  bool fill_rcv_buf(ssize_t size);

  /* Error from send()/sendto(). */
  std::string send_error;

  Packet new_packet( const std::string& s_payload );

  bool is_server() const {
    return server_socket.has_value();
  }
  void set_connection_established(bool connection_established );

  bool establish_connection(void);
public:
  /* Network transport overhead. */
  static const int ADDED_BYTES = 8 /* seqno/nonce */ + 4 /* timestamps */;

  TCPConnection( const char* desired_ip, const char* desired_port );      /* server */
  TCPConnection( const char* key_str, const char* ip, const char* port ); /* client */

  void send( const std::string& s );
  std::string recv( void );

  std::vector<int> fds() const {
    std::vector<int> fds;

    if (server_socket.has_value()) {
      fds.push_back(server_socket->fd());
    }

    if (sock.has_value()) {
      fds.push_back(sock->fd());
    }

    return fds;
  };

  std::string port( void ) const;
  std::string get_key( void ) const { return key.printable_key(); }
  bool get_has_remote_addr( void ) const { return connection_established; }

  uint64_t timeout( void ) const;
  double get_SRTT( void ) const { return SRTT; }

  const Addr& get_remote_addr( void ) const { return remote_addr; }
  socklen_t get_remote_addr_len( void ) const { return remote_addr_len; }

  std::string& get_send_error( void ) { return send_error; }
};
}
#endif