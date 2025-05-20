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

#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>

#include "src/crypto/crypto.h"
#include "src/util/fatal_assert.h"

using namespace Crypto;

namespace Network {
static const unsigned int MOSH_PROTOCOL_VERSION = 2; /* bumped for echo-ack */

uint64_t timestamp( void );
uint16_t timestamp16( void );
uint16_t timestamp_diff( uint16_t tsnew, uint16_t tsold );

class NetworkException : public std::exception
{
public:
  std::string function;
  int the_errno;

private:
  std::string my_what;

public:
  NetworkException( std::string s_function = "<none>", int s_errno = 0 )
    : function( s_function ), the_errno( s_errno ), my_what( function + ": " + strerror( the_errno ) )
  {}
  const char* what() const throw() { return my_what.c_str(); }
  ~NetworkException() throw() {}
};

struct Port
{
  inline explicit constexpr Port( uint16_t p )
    : p( p != 0 ? p : throw std::invalid_argument( "Invalid port number: 0" ) )
  {}
  uint16_t value() const { return p; }
  operator uint16_t() const { return p; }

private:
  uint16_t p;
};

struct PortRange
{
  uint16_t low;
  uint16_t high;
};

enum Direction : uint8_t
{
  TO_SERVER = 0,
  TO_CLIENT = 1
};

uint64_t seq_from_nonce( const Nonce& nonce );
Direction direction_from_nonce( const Nonce& nonce );
Nonce make_nonce( Direction direction, uint64_t seq );

class AddrInfo
{
public:
  struct addrinfo* res;
  AddrInfo( const char* node, const char* service, const struct addrinfo* hints ) : res( NULL )
  {
    int errcode = getaddrinfo( node, service, hints, &res );
    if ( errcode != 0 ) {
      throw NetworkException( std::string( "Bad IP address (" ) + ( node != NULL ? node : "(null)" )
                                + "): " + gai_strerror( errcode ),
                              0 );
    }
  }
  ~AddrInfo() { freeaddrinfo( res ); }

private:
  AddrInfo( const AddrInfo& );
  AddrInfo& operator=( const AddrInfo& );
};

class Addr
{
  union {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr_storage ss;
  } addr;
  socklen_t _len;

public:
  Addr() : addr(), _len( 0 ) { std::memset( &addr, 0, sizeof addr ); }
  Addr( const char* ip, std::optional<uint16_t> port, int sock_type, bool is_server ) : Addr()
  {
    set_from_addrinfo( ip, port, sock_type, is_server );
  }

  void set_from_addrinfo( const char* ip, std::optional<uint16_t> port, int sock_type, bool is_server )
  {
    struct addrinfo hints;
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = sock_type;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | ( is_server ? AI_PASSIVE : 0 );
    char port_str[6];
    if ( port.has_value() ) {
      sprintf( port_str, "%u", port.value() );
    }

    AddrInfo ai( ip, port.has_value() ? port_str : nullptr, &hints );

    set_len( ai.res->ai_addrlen );
    memcpy( &addr.sa, ai.res->ai_addr, len() );
  }

  sockaddr& sa() { return addr.sa; }
  const sockaddr& sa() const { return addr.sa; }

  sockaddr_in& sin() { return addr.sin; }
  const sockaddr_in& sin() const { return addr.sin; }

  sockaddr_in6& sin6() { return addr.sin6; }
  const sockaddr_in6& sin6() const { return addr.sin6; }

  constexpr socklen_t max_len() { return sizeof addr; }

  socklen_t len() const { return _len; }

  void set_len( socklen_t len )
  {
    fatal_assert( len <= max_len() );
    _len = len;
  }

  static Addr getsockname( int fd )
  {
    Addr addr;
    socklen_t len = addr.max_len();
    if ( ::getsockname( fd, &addr.sa(), &len ) < 0 ) {
      throw NetworkException( "getsockname", errno );
    }
    addr.set_len( len );
    return addr;
  }

  Port port() const
  {
    switch ( sa().sa_family ) {
      case AF_INET:
        return Port( ntohs( sin().sin_port ) );
      case AF_INET6:
        return Port( ntohs( sin6().sin6_port ) );
      default:
        throw std::runtime_error( "Addr::port(): Unsupported address family: " + std::to_string( sa().sa_family ) );
    }
  }

  void set_port( uint16_t port )
  {
    switch ( sa().sa_family ) {
      case AF_INET:
        sin().sin_port = ntohs( port );
        break;
      case AF_INET6:
        sin6().sin6_port = ntohs( port );
        break;
      default:
        throw std::runtime_error( "Addr::set_port(): Unsupported address family" );
    }
  }

  std::string ip_address() const
  {
    char buffer[INET6_ADDRSTRLEN] = { 0 };

    switch ( sa().sa_family ) {
      case AF_INET:
        if ( !inet_ntop( AF_INET, &sin().sin_addr, buffer, sizeof( buffer ) ) ) {
          throw NetworkException( "inet_ntop failed for IPv4" );
        }
        break;
      case AF_INET6:
        if ( !inet_ntop( AF_INET6, &sin6().sin6_addr, buffer, sizeof( buffer ) ) ) {
          throw NetworkException( "inet_ntop failed for IPv6" );
        }
        break;
      default:
        throw std::invalid_argument( "Unsupported address family" );
    }

    return std::string( buffer );
  }
};

class Socket
{
private:
  int _fd;
  void close();

public:
  enum class FromFd : int
  {
  };

  int fd( void ) const { return _fd; }
  Socket( int family, int type );
  Socket( FromFd fd );
  ~Socket();

  Socket( const Socket& other );
  Socket& operator=( const Socket& other );

  Socket( Socket&& other );
  Socket& operator=( Socket&& other );
};

enum class NetworkTransportMode
{
  UDP_ONLY,
  TCP_ONLY,
  PREFER_UDP,
};

}

#endif
