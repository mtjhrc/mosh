#include "tcp_connection.h"

#include <iostream>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "compressor.h"
#include "src/network/combined_connection.h"
#include "src/util/dos_assert.h"
#include "src/util/fatal_assert.h"
#include <fcntl.h>
#include <sys/ioctl.h>

using namespace Network;

// All constants in miliseconds
#define TRY_RECONNECT_TIMEOUT 10'000
#define NEXT_RECONNECT_TIMEOUT 4'000
#define DROP_CONNECTION_TIMEOUT 15'000
#define CONNECTION_ESTABLISH_TIMEOUT 60'000
// We specify a hight retransimit timeout of 3 seconds, this makes the higher level assume the messages using TCP
// have always arrived.
#define RETRANSMIT_TIMEOUT 3'000

#ifdef __linux__
#define TCP_THIN_SUPPORT
#endif

/* Read in packet */
TCPConnection::Packet::Packet( Message message )
  : seq( seq_from_nonce( message.nonce ) ), direction( direction_from_nonce( message.nonce ) ),
    payload( std::move( message.text ) )
{}

/* Output from packet */
Message TCPConnection::Packet::toMessage( void )
{
  return Message( make_nonce( direction, seq ), payload );
}

TCPConnection::TCPConnection( Base64Key key, const char* addr, Port port ) /* client */
  : session( key ), direction( TO_SERVER ), server_addr( addr, port.value(), SOCK_STREAM, false )
{
  connect( server_addr );
}

TCPConnection::TCPConnection( Base64Key key, const char* desired_ip, PortRange desired_port_range ) /* server */
  : session( key ), direction( TO_CLIENT ), server_socket( Socket( AF_INET, SOCK_STREAM | SOCK_NONBLOCK ) ),
    server_addr( desired_ip, 0, SOCK_STREAM, true )
{
  int bind_errno = 0;
  bool bind_success = false;

  for ( uint16_t port = desired_port_range.low; port <= desired_port_range.high; ++port ) {
    server_addr.set_port( port );
    if ( ::bind( server_socket->fd(), &server_addr.sa(), server_addr.len() ) >= 0 ) {
      bind_success = true;
      break;
    }
    bind_errno = errno;
  }

  if ( !bind_success ) {
    throw NetworkException( "Failed to bind to any port in range", bind_errno );
  }

  if ( ::listen( server_socket->fd(), 16 ) < 0 ) {
    throw NetworkException( "listen", errno );
  }
}

static void apply_socket_options( int fd )
{
  int flag = 1;
  if ( fcntl( fd, F_SETFL, O_NONBLOCK ) == -1 ) {
    throw NetworkException( "fcntl(F_SETFL, O_NONBLOCK) failed", errno );
  }

  if ( setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof( int ) ) < 0 ) {
    throw NetworkException( "setsockopt(TCP_NODELAY) failed" );
  }

#ifdef TCP_THIN_SUPPORT
  const char* option = getenv( "MOSH_TCP_THIN" );
  if ( option != nullptr && strcmp( option, "0" ) != 0 ) {
    if ( setsockopt( fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &flag, sizeof( int ) ) < 0 ) {
      throw NetworkException( "setsockopt(TCP_THIN_LINEAR_TIMEOUTS) failed" );
    }

    if ( setsockopt( fd, IPPROTO_TCP, TCP_THIN_DUPACK, &flag, sizeof( int ) ) < 0 ) {
      throw NetworkException( "setsockopt(TCP_THIN_DUPACK) failed" );
    }
  }
#endif
}

bool TCPConnection::connect( const Addr& addr )
{
  assert( !is_server() );

  Socket sock( AF_INET, SOCK_STREAM | SOCK_NONBLOCK );
  apply_socket_options( sock.fd() );

  bool is_connected = true;
  if ( ::connect( sock.fd(), &addr.sa(), addr.len() ) < 0 ) {
    auto err = errno;
    if (verbose) {
      fprintf( stderr, "Failed to connect: %s\n", strerror( err ) );
    }
    is_connected = false;
    switch ( err ) {
      case EINPROGRESS:
        break;
      default:
        error = std::string( "TCP connect: " ) + strerror( errno );
        return false;
    }
  }
  last_connect_attempt = timestamp();

  auto ip_addr = Addr::getsockname( sock.fd() ).ip_address();
  for ( auto& stream : streams ) {
    if ( Addr::getsockname( stream.sock.fd() ).ip_address() == ip_addr ) {
      return false;
    }
  }

  streams.emplace_back( ++last_stream_id, addr, std::move( sock ), is_connected );
  return true;
}

uint32_t TCPConnection::accept( void )
{
  assert( is_server() );

  Addr remote_addr;

  socklen_t len = remote_addr.max_len();
  int client_fd = ::accept( server_socket->fd(), &remote_addr.sa(), &len );
  if ( client_fd < 0 ) {
    auto err = errno;
    switch ( err ) {
#if EWOULDBLOCK != EAGAIN
      case EWOULDBLOCK:
#endif
      case EAGAIN:
        return 0;
      default:
        error = std::string( "TCP accept: " ) + strerror( err );
        return 0;
    }
  }
  remote_addr.set_len( len );
  apply_socket_options( client_fd );

  Socket sock( Socket::FromFd { client_fd } );
  if ( streams.size() > MAX_STREAMS ) {
    return false;
  }
  uint32_t new_stream_id = ++last_stream_id;
  streams.emplace_back( new_stream_id, remote_addr, std::move( sock ), true );
  return new_stream_id;
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

std::optional<TCPConnection::packet_len_t> TCPConnection::TCPStream::send_bytes( const std::string& msg,
                                                                                 packet_len_t index )
{
  assert( index <= msg.size() );
  assert( msg.size() - index <= MAX_PACKET_LEN );
  ssize_t result = ::send( sock.fd(), msg.data() + index, msg.size() - index, MSG_DONTWAIT | MSG_NOSIGNAL );
  if ( result < 0 && errno == EAGAIN ) {
    return std::nullopt;
  } else if ( result < 0 && errno != EAGAIN ) {
    is_connected = false;
    error = std::string( "TCP send: " ) + strerror( errno );
  }
  return result;
}

bool TCPConnection::TCPStream::finish_send( void )
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

std::optional<TCPConnection::packet_len_t> TCPConnection::TCPStream::send( const std::string& msg )
{
  if ( !finish_send() ) {
    return std::nullopt;
  }

  std::optional sent_bytes = send_bytes( msg, 0 );
  if ( sent_bytes && sent_bytes.value() < msg.size() ) {
    send_buffer = std::move( msg );
    send_buffer_index = sent_bytes.value();
  }

  return sent_bytes;
}

void TCPConnection::TCPStream::check_if_connected( void )
{
  int err = 0;
  socklen_t len = sizeof err;
  if ( getsockopt( sock.fd(), SOL_SOCKET, SO_ERROR, &err, &len ) < 0 ) {
    throw NetworkException( "getsockopt(SOL_SOCKET, SO_ERROR)" );
  }

  if ( err != 0 ) {
    dead = true;
    error = std::string( "connect: " ) + strerror( err );
  }
  is_connected = true;
}

void TCPConnection::send( const Instruction& inst )
{
  Packet packet = new_packet( get_compressor().compress_str( inst.SerializeAsString() ) );
  std::string msg = session.encrypt( packet.toMessage() );

  prepend_msg_size( msg );

  for ( auto& stream : streams ) {
    if (stream.last_instr.has_sent(inst)) {
      stream.finish_send();
      continue;
    }

    std::optional packet_len = stream.send( msg );
    if ( !packet_len ) {
      send_dropped( stream.stream_id, inst );
    } else {
      stream.last_instr.update(inst);
      if ( report_fn ) {
        report_fn( TcpSendReport {
          stream.stream_id,
          inst,
          packet_len.value(),
          static_cast<uint32_t>( msg.size() ),
          get_RTO(),
          streams.front().srtt,
        } );
      }
    }
  }
}

void TCPConnection::send_dropped( uint32_t stream_id, const TransportBuffers::Instruction& inst )
{
  if ( report_fn ) {
    report_fn( TcpSendDroppedReport {
      stream_id,
      inst,
      get_RTO(),
      get_SRTT(),
    } );
  }
}

std::string TCPConnection::clear_send_error( void )
{
  return std::exchange( error, "" );
}

bool TCPConnection::TCPStream::fill_rcv_buf( size_t size )
{
  if ( rcv_buf.size() != size ) {
    rcv_buf.resize( size );
  }

  while ( rcv_index < size ) {
    ssize_t ret = ::recv( sock.fd(), rcv_buf.data() + rcv_index, size - rcv_index, MSG_DONTWAIT | MSG_NOSIGNAL );
    if ( ret < 0 ) {
      switch ( errno ) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
          return false;
        case ETIMEDOUT:
        default:
          error = strerror( errno );
          dead = true;
          return false;
      }
    } else if ( ret == 0 ) {
      dead = true;
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

std::optional<std::string_view> TCPConnection::TCPStream::recv_bytes( void )
{
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
  return rcv_buf;
}

std::optional<Instruction> TCPConnection::recv( void )
{
  std::optional<Instruction> result;
  for ( auto& stream : streams ) {
    std::optional<std::string_view> maybe_packet = stream.recv_bytes();
    if ( !maybe_packet ) {
      continue;
    }
    std::string_view packet = maybe_packet.value();

    try {
      Packet p( session.decrypt( packet.data(), packet.size() ) );
      // Since we are using TCP, we should never receive an out-of-order/old data (on the same TCP connection)
      // This is not a security concern, because the upper layer is able to handle out-of-order/duplicate
      // instructions, but this is likely an attempt at denial of service of the server by sending wrong data to it.
      dos_assert( p.direction == ( is_server() ? TO_SERVER : TO_CLIENT ) );
      dos_assert( stream.expecting_seq_number == 0 || p.seq >= stream.expecting_seq_number );
      stream.expecting_seq_number = p.seq + 1;

      Instruction inst;
      fatal_assert( inst.ParseFromString( get_compressor().uncompress_str( p.payload ) ) );

      if ( report_fn ) {
        report_fn( TcpRecvReport {
          stream.stream_id,
          inst,
        } );
      }

      result = inst;
    } catch ( CryptoException ) {
      stream.dead = true;
      throw;
    }
  }

  return result;
}

std::optional<Port> TCPConnection::tcp_port( void ) const
{
  assert( is_server() || !streams.empty() );
  Addr local_addr = Addr::getsockname( is_server() ? server_socket->fd() : streams.front().sock.fd() );
  return local_addr.port();
}

uint64_t TCPConnection::get_RTO( void ) const
{
  return RETRANSMIT_TIMEOUT;
}

TCPConnection::Packet TCPConnection::new_packet( const std::string& s_payload )
{
  TCPConnection::Packet p( direction, seq_counter.next(), s_payload );
  return p;
}

void TCPConnection::TCPStream::update_conn_stats( void )
{
  // Do not obtain TCP connection information from non-connected streams
  if ( !is_connected ) {
    last_heard_ms = 0;
    return;
  }

  struct tcp_info info;
  socklen_t info_len = sizeof( info );

  // Retrieve TCP_INFO from the socket
  if ( getsockopt( sock.fd(), SOL_TCP, TCP_INFO, &info, &info_len ) != 0 ) {
    perror( "getsockopt TCPINFO" );
  }

  // The info struct stores microseconds, convert to floating point seconds
  srtt = (double)info.tcpi_rtt / 1000;
  last_heard_ms = info.tcpi_last_ack_recv;
  timeout = info.tcpi_rto;
}

double TCPConnection::get_SRTT( void ) const
{
  if ( streams.empty() ) {
    return 1'000;
  } else {
    return streams.front().srtt;
  };
}

void TCPConnection::prune_streams()
{
  auto it = std::remove_if( streams.begin(), streams.end(), [&]( const auto& stream ) {
    return stream.dead || ( stream.is_connected && stream.last_heard_ms >= DROP_CONNECTION_TIMEOUT )
           || ( !stream.is_connected && stream.last_heard_ms >= CONNECTION_ESTABLISH_TIMEOUT );
  } );

  if ( verbose ) {
    fprintf( stderr,
             "Have %u streams, removing %u\n",
             (unsigned int)streams.size(),
             (unsigned int)std::distance( it, streams.end() ) );
  }

  streams.erase( it, streams.end() );
}

void TCPConnection::register_select( Select& select )
{
  for ( auto& stream : streams ) {
    stream.update_conn_stats();
  }

  bool has_working_conn = std::find_if( streams.begin(),
                                        streams.end(),
                                        []( const auto& s ) { return s.last_heard_ms <= TRY_RECONNECT_TIMEOUT; } )
                          != streams.end();

  prune_streams();

  if ( verbose ) {
    fprintf( stderr,
             "TCP enabled:%d streams_empty:%d, has_working_conn:%d, since_last_connect_attempt:%lu\n",
             enabled,
             streams.empty(),
             has_working_conn,
             timestamp() - last_connect_attempt );
  }
  if ( !is_server() && enabled && ( streams.empty() || !has_working_conn )
       && timestamp() - last_connect_attempt >= NEXT_RECONNECT_TIMEOUT ) {
    connect( server_addr );
  }

  if ( server_socket.has_value() ) {
    select.add_read_fd( server_socket->fd() );
    select.add_write_fd( server_socket->fd() );
  }

  for ( const auto& stream : streams ) {
    select.add_read_fd( stream.sock.fd() );

    if ( ( stream.is_connected && !stream.send_buffer.empty() ) || !stream.is_connected ) {
      select.add_write_fd( stream.sock.fd() );
    }
  }
}

Actions TCPConnection::wakeup( Select& select )
{
  Actions actions;
  uint32_t new_stream_id = 0;
  if ( server_socket && select.read( server_socket->fd() ) ) {
    new_stream_id = accept();
  }

  for ( auto& stream : streams ) {
    if ( !stream.is_connected && select.write( stream.sock.fd() ) ) {
      stream.check_if_connected();
    }

    if ( stream.is_connected ) {
      if ( !stream.send_buffer.empty() && select.write( stream.sock.fd() ) ) {
        stream.finish_send();
      }
      actions.recv |= stream.stream_id == new_stream_id || select.read( stream.sock.fd() );
    }
  }

  return actions;
}

const Addr* TCPConnection::get_remote_addr( void ) const
{
  for ( auto& stream : streams ) {
    if ( stream.is_connected ) {
      return &stream.remote_addr;
    }
  }
  return nullptr;
}

bool TCPConnection::has_remote_addr( void ) const
{
  return get_remote_addr() != nullptr;
}
