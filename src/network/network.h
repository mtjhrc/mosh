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
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

#include "src/crypto/crypto.h"

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

enum Direction
{
  TO_SERVER = 0,
  TO_CLIENT = 1
};

union Addr {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct sockaddr_storage ss;
};

class Socket
{
private:
  int _fd;

public:
  int fd( void ) const { return _fd; }
  Socket( int family, int type );
  ~Socket();

  Socket( const Socket& other );
  Socket& operator=( const Socket& other );
};

}

#endif
