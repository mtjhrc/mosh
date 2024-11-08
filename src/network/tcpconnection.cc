#include "tcpconnection.h"

#include <iostream>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "compressor.h"
#include "src/network/combinedconnection.h"
#include "src/util/dos_assert.h"
#include "src/util/fatal_assert.h"

using namespace Network;

void TCPConnection::set_connection_established( bool connection_established )
{
  if ( this->connection_established && !connection_established ) {
    // Drop any partial packet in rcv_buf
    rcv_current_packet_len = 0;
    rcv_index = 0;
    rcv_buf.clear();
    // Close the connection on our side
    sock = std::nullopt;
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
    int client_fd = ::accept( server_socket->fd(), (struct sockaddr*)&remote_addr.addr.sin, &remote_addr.len );
    if ( client_fd < 0 ) {
      if ( errno != EAGAIN ) {
        send_error = std::string( "TCP accept: " ) + strerror( errno );
      }
      return false;
    }
    sock = Socket( Fd { client_fd } );
  } else {
    if ( !sock ) {
      sock = Socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK );
    }
    if ( ::connect( sock->fd(), (struct sockaddr*)&remote_addr, remote_addr.len ) < 0 ) {
      set_connection_established( false );
      switch ( errno ) {
        case EINPROGRESS:
        case EALREADY:
          return false;
        case EISCONN:
          break;
        default:
          send_error = std::string( "TCP connect: " ) + strerror( errno );
      }
    }
  }

  set_connection_established( true );
  return true;
}

TCPConnection::TCPConnection( Base64Key key, const char* desired_ip, PortRange desired_port_range ) /* server */
  : server_socket( Socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK ) ), session( key ), direction( TO_CLIENT ),
    saved_timestamp( -1 ), saved_timestamp_received_at( 0 )
{
  sockaddr_in server_addr;
  memset( &server_addr, 0, sizeof server_addr );
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr( desired_ip );

  int bind_errno;
  bool bind_success = false;

  for ( uint16_t port = desired_port_range.low; port <= desired_port_range.high; ++port ) {
    server_addr.sin_port = htons( port );
    if ( ::bind( server_socket->fd(), (struct sockaddr*)&server_addr, sizeof( server_addr ) ) >= 0 ) {
      bind_success = true;
      break;
    }
    fprintf( stderr, "bind %d %s\n", port, strerror( errno ) );
    bind_errno = errno;
  }

  if ( !bind_success ) {
    throw NetworkException( "Failed to bind to any port in range", bind_errno );
  }

  if ( ::listen( server_socket->fd(), 16 ) < 0 ) {
    throw NetworkException( "listen", errno );
  }
}

TCPConnection::TCPConnection( Base64Key key, const char* addr, Port port ) /* client */
  : session( key ), direction( TO_SERVER ), saved_timestamp( -1 ), saved_timestamp_received_at( 0 ),
    expected_receiver_seq( 0 ), send_error()
{
  remote_addr.addr.sin.sin_family = AF_INET;
  remote_addr.addr.sin.sin_port = htons( port.value() );
  remote_addr.addr.sin.sin_addr.s_addr = inet_addr( addr );
  remote_addr.len = sizeof( sockaddr_in );

  establish_connection();
}

static void prepend_msg_size( std::string& msg )
{
  auto host_order = msg.size();
  assert( host_order <= UINT32_MAX );
  assert( host_order != 0 );
  uint32_t net_ord = htobe32( host_order );
  msg.insert( 0, reinterpret_cast<char*>( &net_ord ), 4 );
}

static uint32_t size_from_network_order( uint32_t net_order )
{
  return be32toh( net_order );
}

std::optional<TCPConnection::packet_len_t> TCPConnection::send_bytes( const std::string& msg, packet_len_t index )
{
  assert( msg.size() >= index );
  assert( msg.size() - index <= MAX_PACKET_LEN );
  ssize_t result = ::send( sock->fd(), msg.data() + index, msg.size() - index, MSG_DONTWAIT | MSG_NOSIGNAL );
  if ( result < 0 && errno == EAGAIN ) {
    return std::nullopt;
  } else if ( result < 0 && errno != EAGAIN ) {
    set_connection_established( false );
    send_error = std::string( "TCP send: " ) + strerror( errno );
  }
  return result;
}

bool TCPConnection::finish_send( void )
{
  if ( send_buffer.empty() ) {
    return true;
  }

  auto sent = send_bytes( send_buffer, send_buffer_index );
  if ( !sent ) {
    return false;
  }
  send_buffer_index += sent.value();

  if ( send_buffer_index >= send_buffer.size() ) {
    send_buffer.clear();
    send_buffer_index = 0;
    return true;
  }

  return false;
}

void TCPConnection::send( const Instruction& inst )
{
  if ( !establish_connection() ) {
    send_dropped( inst );
    return;
  }
  assert( sock );
  if ( !finish_send() ) {
    send_dropped( inst );
    return;
  }

  Packet packet = new_packet( get_compressor().compress_str( inst.SerializeAsString() ) );
  std::string msg = session.encrypt( packet.toMessage() );

  prepend_msg_size( msg );

  std::optional<packet_len_t> sent_bytes = send_bytes( msg, 0 );
  if ( !sent_bytes ) {
    send_dropped( inst );
  } else if ( sent_bytes.value() < msg.size() ) { // partial write
    send_buffer = std::move( msg );
    send_buffer_index = sent_bytes.value();
    return;
  }

  if ( report_fn ) {
    report_fn( TcpSendReport {
      .inst = inst,
      .sent_len = sent_bytes.value(),
      .msg_len = static_cast<uint32_t>( msg.size() ),
      .timeout = timeout(),
      .srtt = SRTT,
    } );
  }
}

void TCPConnection::send_dropped( const TransportBuffers::Instruction& inst )
{
  if ( report_fn ) {
    report_fn( TcpSendDroppedReport {
      .inst = inst,
      .timeout = timeout(),
      .srtt = SRTT,
    } );
  }
  // TODO: adjust timers
}

std::string TCPConnection::clear_send_error( void )
{
  return std::exchange( send_error, "" );
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

std::optional<Instruction> TCPConnection::recv( void )
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
    return std::nullopt;
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

  Instruction inst;
  fatal_assert( inst.ParseFromString( get_compressor().uncompress_str( p.payload ) ) );

  if ( report_fn ) {
    report_fn( TcpRecvReport {
      .inst = inst,
    } );
  }
  return inst;
}

std::optional<Port> TCPConnection::tcp_port( void ) const
{
  Addr local_addr = Addr::getsockname( is_server() ? server_socket->fd() : sock->fd() );
  return local_addr.port();
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
