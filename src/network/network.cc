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
#include "src/network/network.h"
#include "src/include/config.h"

#include <unistd.h>

#include "config.h"
#include "src/util/fatal_assert.h"
#include "src/util/timestamp.h"

using namespace Network;

uint64_t Network::timestamp( void )
{
  return frozen_timestamp();
}

uint16_t Network::timestamp16( void )
{
  uint16_t ts = timestamp() % 65536;
  if ( ts == uint16_t( -1 ) ) {
    ts++;
  }
  return ts;
}

uint16_t Network::timestamp_diff( uint16_t tsnew, uint16_t tsold )
{
  int diff = tsnew - tsold;
  if ( diff < 0 ) {
    diff += 65536;
  }

  assert( diff >= 0 );
  assert( diff <= 65535 );

  return diff;
}

Socket::Socket( int family, int type ) : _fd( socket( family, type, 0 ) )
{
  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }
}

Socket::~Socket()
{
  fatal_assert( close( _fd ) == 0 );
}

Socket::Socket( const Socket& other ) : _fd( dup( other._fd ) )
{
  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }
}

Socket& Socket::operator=( const Socket& other )
{
  if ( dup2( other._fd, _fd ) < 0 ) {
    throw NetworkException( "socket", errno );
  }

  return *this;
}