#include "tcpconnection.h"

#include <iostream>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "src/network/connection.h"
#include "src/util/dos_assert.h"

using namespace Network;

void TCPConnection::set_connection_established( bool connection_established )
{
  // If the connection is resetting, we need to reset the rcv buffer
  if ( this->connection_established && !connection_established ) {
    rcv_current_packet_len = 0;
    rcv_index = 0;
    rcv_buf.clear();
  }
  this->connection_established = connection_established;
}

bool TCPConnection::establish_connection( void )
{
  if ( connection_established ) {
    return true;
  }

  if ( is_server() ) {
    assert( server_socket.has_value() );
    int client_fd = ::accept( server_socket->fd(), (struct sockaddr*)&remote_addr.sin, &remote_addr_len );
    if ( client_fd < 0 ) {
      throw NetworkException( "establish_connection (accept)", errno );
    }
    sock = Socket( Fd { client_fd } );
  } else {
    assert( sock.has_value() );
    if ( ::connect( sock->fd(), (struct sockaddr*)&remote_addr, remote_addr_len ) < 0 ) {
      set_connection_established( false );
      switch ( errno ) {
        case EISCONN:
          // close to current socket and try to reconnect again
          sock = Socket( AF_INET, SOCK_STREAM );
          return false;
        default:
          throw NetworkException( "establish_connection (connect)", errno );
      }
    }
  }

  uint64_t tcp_timeout = timeout();
  if ( ::setsockopt( sock->fd(), IPPROTO_TCP, TCP_USER_TIMEOUT, &tcp_timeout, sizeof( tcp_timeout ) ) < 0 ) {
    throw NetworkException( "setsockopt(..., IPPROTO_TCP, TCP_USER_TIMEOUT, ...)", errno );
  }

  connection_established = true;
  return true;
}

static uint16_t parse_port_number(const char* port_str ) {
  if ( port_str == nullptr) {
    throw NetworkException("Port number not specified", EINVAL);
  }

  char* endptr;
  errno = 0;
  long int value = std::strtol( port_str, &endptr, 10);

  // Check for various possible errors
  if (errno !=0 || value < 0 || value > UINT16_MAX || endptr== port_str || *endptr != '\0') {
    throw NetworkException("Invalid port number", EINVAL);
  }

  return static_cast<uint16_t>(value);
}

TCPConnection::TCPConnection( const char* desired_ip, const char* desired_port ) /* server */
  : server_socket( Socket( AF_INET, SOCK_STREAM ) ), sock( std::nullopt ), remote_addr(), remote_addr_len( 0 ),
    key(), session( key ), direction( TO_CLIENT ), saved_timestamp( -1 ), saved_timestamp_received_at( 0 ),
    expected_receiver_seq( 0 ), send_error()
{ // server

  /* convert udp_port numbers */
  int desired_port_low = -1;
  int desired_port_high = -1;

  if ( desired_port == nullptr
       || !Connection::parse_portrange( desired_port, desired_port_low, desired_port_high ) ) {
    throw NetworkException( "Invalid udp_port range", 0 );
  }

  sockaddr_in server_addr;
  memset( &server_addr, 0, sizeof server_addr );
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr( desired_ip );

  int bind_errno;
  bool bind_success = false;

  for ( int port = desired_port_low; port <= desired_port_high; ++port ) {
    server_addr.sin_port = htons( port );
    if ( ::bind( server_socket->fd(), (struct sockaddr*)&server_addr, sizeof( server_addr ) ) >= 0 ) {
      bind_success = true;
      break;
    }
    fprintf( stderr, "bind %d %s\n", port, strerror( errno ) );
    bind_errno = errno;
  }

  if ( !bind_success ) {
    throw NetworkException( "Failed to bind to any port in range", errno );
  }

  if ( ::listen( server_socket->fd(), 1 ) < 0 ) {
    throw NetworkException( "listen", bind_errno );
  }
}

TCPConnection::TCPConnection( const char* key_str, const char* ip, const char* port ) /* client */
  : server_socket( std::nullopt ), sock( Socket( AF_INET, SOCK_STREAM ) ), remote_addr(), remote_addr_len( 0 ),
    key( key_str ), session( key ), direction( TO_SERVER ), saved_timestamp( -1 ), saved_timestamp_received_at( 0 ),
    expected_receiver_seq( 0 ), send_error()
{
  uint16_t parsed_port = parse_port_number(port);

  remote_addr.sin.sin_family = AF_INET;
  remote_addr.sin.sin_port = htons( parsed_port );
  remote_addr.sin.sin_addr.s_addr = inet_addr( ip );
  remote_addr_len = sizeof( sockaddr_in );
}

static std::string size_to_network_order_string( uint32_t host_order )
{
  assert( host_order != 0 );
  uint32_t net_ord = htobe32( host_order );
  assert( net_ord != 0 );
  return std::string( (char*)&net_ord, sizeof( net_ord ) );
}

static uint32_t size_from_network_order( uint32_t net_order )
{
  return be32toh( net_order );
}

void TCPConnection::send( const std::string& s )
{
  if ( !establish_connection() ) {
    return;
  }

  Packet packet = new_packet( s );
  std::string payload = session.encrypt( packet.toMessage() );

  auto size_str = size_to_network_order_string( payload.size() );

  std::string msg = size_str + payload;
  size_t total_sent = 0;

  while ( total_sent < msg.size() ) {
    ssize_t ret = ::send( sock->fd(), msg.data() + total_sent, msg.size() - total_sent, MSG_NOSIGNAL );
    if ( ret < 0 && errno != EAGAIN ) {
      set_connection_established( false );
      throw NetworkException( "send", errno );
    }
    total_sent += ret;
  }
}

bool TCPConnection::fill_rcv_buf( ssize_t size )
{
  if ( rcv_buf.size() != size ) {
    rcv_buf.resize( size );
  }

  while ( rcv_index < size ) {
    ssize_t ret = ::recv( sock->fd(), rcv_buf.data() + rcv_index, size - rcv_index, MSG_DONTWAIT | MSG_NOSIGNAL );
    if ( ret < 0 ) {
      switch ( errno ) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
          return false;
        case ETIMEDOUT:
          set_connection_established( false );
          return false;
        default:
          set_connection_established( false );
          throw NetworkException( "recv", errno );
      }
    } else if ( ret == 0 ) {
      set_connection_established( false );
      break;
    } else {
      rcv_index += ret;
    }
  }

  if ( rcv_index == size ) {
    rcv_index = 0;
    return true;
  }

  return false;
}

std::string TCPConnection::recv( void )
{
  if ( !establish_connection() ) {
    return {};
  }

  // make sure we have the packet length
  if ( rcv_current_packet_len == 0 ) {
    if ( !fill_rcv_buf( sizeof( packet_len_t ) ) ) {
      return {};
    }
    rcv_current_packet_len = size_from_network_order( *(uint32_t*)rcv_buf.data() );
  }

  if ( !fill_rcv_buf( rcv_current_packet_len ) ) {
    return {};
  }
  assert( rcv_buf.size() == rcv_current_packet_len );
  rcv_current_packet_len = 0;

  Packet p( session.decrypt( rcv_buf.data(), rcv_buf.size() ) );

  // prevent malicious playback to sender
  dos_assert( p.direction == ( is_server() ? TO_SERVER : TO_CLIENT ) );
  // We don't expect receive out-of-order packets for TCP
  dos_assert( p.seq >= expected_receiver_seq );

  // This is security-sensitive because a replay attack could otherwise
  // screw up the timestamp and targeting
  expected_receiver_seq = p.seq + 1;

  if ( p.timestamp != uint16_t( -1 ) ) {
    saved_timestamp = p.timestamp;
    saved_timestamp_received_at = timestamp();
  }

  if ( p.timestamp_reply != uint16_t( -1 ) ) {
    uint16_t now = timestamp16();
    double R = timestamp_diff( now, p.timestamp_reply );

    if ( R < 5000 ) {   /* ignore large values, e.g. server was Ctrl-Zed */
      if ( !RTT_hit ) { /* first measurement */
        SRTT = R;
        RTTVAR = R / 2;
        RTT_hit = true;
      } else {
        const double alpha = 1.0 / 8.0;
        const double beta = 1.0 / 4.0;

        RTTVAR = ( 1 - beta ) * RTTVAR + ( beta * fabs( SRTT - R ) );
        SRTT = ( 1 - alpha ) * SRTT + ( alpha * R );
      }
    }
  }

  return p.payload;
}

std::string TCPConnection::port( void ) const
{
  Addr local_addr;
  socklen_t addrlen = sizeof( local_addr );

  if ( getsockname( is_server() ? server_socket->fd() : sock->fd(), &local_addr.sa, &addrlen ) < 0 ) {
    throw NetworkException( "getsockname", errno );
  }

  char serv[NI_MAXSERV];
  int errcode = getnameinfo( &local_addr.sa, addrlen, NULL, 0, serv, sizeof( serv ), NI_DGRAM | NI_NUMERICSERV );
  if ( errcode != 0 ) {
    throw NetworkException( std::string( "udp_port: getnameinfo: " ) + gai_strerror( errcode ), 0 );
  }

  return { serv };
}

uint64_t TCPConnection::timeout( void ) const
{
  uint64_t RTO = lrint( ceil( SRTT + 4 * RTTVAR ) );
  if ( RTO < MIN_RTO ) {
    RTO = MIN_RTO;
  } else if ( RTO > MAX_RTO ) {
    RTO = MAX_RTO;
  }
  return RTO;
}

Packet TCPConnection::new_packet( const std::string& s_payload )
{
  uint16_t outgoing_timestamp_reply = -1;

  uint64_t now = timestamp();

  if ( now - saved_timestamp_received_at < 1000 ) { /* we have a recent received timestamp */
    /* send "corrected" timestamp advanced by how long we held it */
    outgoing_timestamp_reply = saved_timestamp + ( now - saved_timestamp_received_at );
    saved_timestamp = -1;
    saved_timestamp_received_at = 0;
  }

  Packet p( direction, timestamp16(), outgoing_timestamp_reply, s_payload );

  return p;
}
