/*
Mosh: the mobile shell
Copyright 2012 Keith Winstein

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

In addition, as a special exception, the copyright holders give
permission to link the code of portions of this program with the
OpenSSL library under certain conditions as described in each
individual source file, and distribute linked combinations including
the two.

You must obey the GNU General Public License in all respects for all
of the code used other than OpenSSL. If you modify file(s) with this
exception, you may extend this exception to your version of the
file(s), but you are not obligated to do so. If you do not wish to do
so, delete this exception statement from your version. If you delete
this exception statement from all source files in the program, then
also delete it here.
*/
#ifndef UDP_CONNECTION_HPP
#define UDP_CONNECTION_HPP

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

#include "connection.h"
#include "network.h"
#include "src/crypto/crypto.h"
#include "transportfragment.h"

namespace Network {

class Packet
{
public:
  const uint64_t seq;
  Direction direction;
  uint16_t timestamp, timestamp_reply;
  std::string payload;

  Packet( Direction s_direction, uint16_t s_timestamp, uint16_t s_timestamp_reply, const std::string& s_payload )
    : seq( Crypto::unique() ), direction( s_direction ), timestamp( s_timestamp ),
      timestamp_reply( s_timestamp_reply ), payload( s_payload )
  {}

  Packet( const Message& message );

  Message toMessage( void );
};

class UDPConnection final : public Connection
{
private:
  /*
   * For IPv4, guess the typical (minimum) header length;
   * fragmentation is not dangerous, just inefficient.
   */
  static const int IPV4_HEADER_LEN = 20 /* base IP header */
                                     + 8 /* UDP */;
  /*
   * For IPv6, we don't want to ever have MTU issues, so make a
   * conservative guess about header size.
   */
  static const int IPV6_HEADER_LEN = 40   /* base IPv6 header */
                                     + 16 /* 2 minimum-sized extension headers */
                                     + 8 /* UDP */;
  /* Application datagram MTU. For constructors and fallback. */
  static const int DEFAULT_SEND_MTU = 500;
  /*
   * IPv4 MTU. Don't use full Ethernet-derived MTU,
   * mobile networks have high tunneling overhead.
   *
   * As of July 2016, VPN traffic over Amtrak Acela wifi seems to be
   * dropped if tunnelled packets are 1320 bytes or larger.  Use a
   * 1280-byte IPv4 MTU for now.
   *
   * We may have to implement ICMP-less PMTUD (RFC 4821) eventually.
   */
  static const int DEFAULT_IPV4_MTU = 1280;
  /* IPv6 MTU. Use the guaranteed minimum to avoid fragmentation. */
  static const int DEFAULT_IPV6_MTU = 1280;

  static const uint64_t MIN_RTO = 50;   /* ms */
  static const uint64_t MAX_RTO = 1000; /* ms */

  static const int PORT_RANGE_LOW = 60001;
  static const int PORT_RANGE_HIGH = 60999;

  static const unsigned int SERVER_ASSOCIATION_TIMEOUT = 40000;
  static const unsigned int PORT_HOP_INTERVAL = 10000;

  static const unsigned int MAX_PORTS_OPEN = 10;
  static const unsigned int MAX_OLD_SOCKET_AGE = 60000;

  static const int CONGESTION_TIMESTAMP_PENALTY = 500; /* ms */

  bool try_bind( const char* addr, int port_low, int port_high );
  std::deque<Socket> socks;
  bool has_remote_addr_;
  Addr remote_addr;

  bool server;

  int MTU; /* application datagram MTU */

  Base64Key key;
  Session session;

  void setup( void );

  Direction direction;
  uint16_t saved_timestamp;
  uint64_t saved_timestamp_received_at;
  uint64_t expected_receiver_seq;

  uint64_t last_heard;
  uint64_t last_port_choice;
  uint64_t last_roundtrip_success; /* transport layer needs to tell us this */

  bool RTT_hit;
  double SRTT;
  double RTTVAR;

  /* Error from send()/sendto(). */
  std::string send_error;

  Fragmenter fragmenter;
  FragmentAssembly fragments;

  ReportFunction report_fn;

  Packet new_packet( const std::string& s_payload );

  void add_socket( int family );
  void hop_port( void );

  int sock( void ) const
  {
    assert( !socks.empty() );
    return socks.back().fd();
  }

  void prune_sockets( void );

  std::string recv_one( int sock_to_recv );

  void set_MTU( int family );

  void send_fragment( const std::string& inst );
  std::string recv_fragment( void );

public:
  /* Network transport overhead. */
  static const int ADDED_BYTES = 8 /* seqno/nonce */ + 4 /* timestamps */;

  // Server
  UDPConnection( Base64Key key, const char* desired_ip, PortRange desired_port );

  // Client
  UDPConnection( Base64Key key, const char* ip, Port port);

  void set_report_function(Connection::ReportFunction report_fn) override {
      this->report_fn = std::move(report_fn);
  };

  void send( const TransportBuffers::Instruction& inst ) override;
  bool finish_send( void ) override {};
  std::string clear_send_error( void ) override;

  std::optional<TransportBuffers::Instruction> recv( void ) override;

  std::vector<int> fds_notify_read( void ) const override;
  std::vector<int> fds_notify_write( void ) const override {
    return {};
  };

  std::optional<Port> udp_port( void ) const override;
  std::optional<Port> tcp_port( void ) const override {
    return std::nullopt;
  }

  uint64_t timeout( void ) const override;
  double get_SRTT( void ) const override { return SRTT; }

  const Addr* get_remote_addr( void ) const override { return has_remote_addr_? &remote_addr : nullptr; }
  bool has_remote_addr( void ) const override { return has_remote_addr_; }

  void set_last_roundtrip_success( uint64_t timestamp ) override { last_roundtrip_success = timestamp; }
};
}

#endif // UDP_CONNECTION_HPP