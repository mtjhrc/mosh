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

#include "src/include/config.h"
#include "src/include/version.h"

#include <climits>
#include <cstdlib>

#include <unistd.h>

#include "src/crypto/crypto.h"
#include "src/util/fatal_assert.h"
#include "src/util/locale_utils.h"
#include "stmclient.h"

/* These need to be included last because of conflicting defines. */
/*
 * stmclient.h includes termios.h, and that will break termio/termios pull in on Solaris.
 * The solution is to include termio.h also.
 * But Mac OS X doesn't have termio.h, so this needs a guard.
 */
#ifdef HAVE_TERMIO_H
#include <termio.h>
#endif

#if defined HAVE_NCURSESW_CURSES_H
#include <ncursesw/curses.h>
#include <ncursesw/term.h>
#elif defined HAVE_NCURSESW_H
#include <ncursesw.h>
#include <term.h>
#elif defined HAVE_NCURSES_CURSES_H
#include <ncurses/curses.h>
#include <ncurses/term.h>
#elif defined HAVE_NCURSES_H
#include <ncurses.h>
#include <term.h>
#elif defined HAVE_CURSES_H
#include <curses.h>
#include <term.h>
#else
#error "SysV or X/Open-compatible Curses header file required"
#endif

static void print_version( FILE* file )
{
  fputs( "mosh-client (" PACKAGE_STRING ") [build " BUILD_VERSION "]\n"
         "Copyright 2012 Keith Winstein <mosh-devel@mit.edu>\n"
         "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
         "This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n",
         file );
}

static void print_usage( FILE* file, const char* argv0 )
{
  print_version( file );
  fprintf( file,
           "\nUsage: %s [-# 'ARGS'] IP UDP_PORT [TCP_PORT]\n"
           "       %s -c\n",
           argv0,
           argv0 );
}

static void print_colorcount( void )
{
  /* check colors */
  setupterm( (char*)0, 1, (int*)0 );

  char colors_name[] = "colors";
  int color_val = tigetnum( colors_name );
  if ( color_val == -2 ) {
    fprintf( stderr, "Invalid terminfo numeric capability: %s\n", colors_name );
  }

  printf( "%d\n", color_val );
}

Network::Port parse_port_number_or_exit( const char* prog_name, const char* port_name, const char* port )
{
  errno = 0;
  char* end;
  long value = strtol( port, &end, 10 );
  if ( errno != 0 || *end != '\0' || value <= 1 || value > UINT16_MAX ) {
    fprintf( stderr, "%s: Bad %s udp_port (%s)\n\n", prog_name, port_name, port );
    print_usage( stderr, port_name );
    exit( 1 );
  }
  return Network::Port( static_cast<uint16_t>( value ) );
}

#ifdef NACL
int mosh_main( int argc, char* argv[] )
#else
int main( int argc, char* argv[] )
#endif
{
  unsigned int verbose = 0;
  /* For security, make sure we don't dump core */
  Crypto::disable_dumping_core();

  /* Detect edge case */
  fatal_assert( argc > 0 );

  /* Get arguments */
  for ( int i = 1; i < argc; i++ ) {
    if ( 0 == strcmp( argv[i], "--help" ) ) {
      print_usage( stdout, argv[0] );
      exit( 0 );
    }
    if ( 0 == strcmp( argv[i], "--version" ) ) {
      print_version( stdout );
      exit( 0 );
    }
  }

  int opt;
  while ( ( opt = getopt( argc, argv, "#:cv" ) ) != -1 ) {
    switch ( opt ) {
      case '#':
        // Ignore the original arguments to mosh wrapper
        break;
      case 'c':
        print_colorcount();
        exit( 0 );
        break;
      case 'v':
        verbose++;
        break;
      default:
        print_usage( stderr, argv[0] );
        exit( 1 );
        break;
    }
  }

  int num_args = argc - optind;

  char* ip = nullptr;
  std::optional<Network::Port> desired_udp_port;
  std::optional<Network::Port> desired_tcp_port;

  if ( num_args < 2 || num_args > 3 ) {
    print_usage( stderr, argv[0] );
    exit( 1 );
  }

  ip = argv[optind];
  desired_udp_port = parse_port_number_or_exit( argv[0], "UDP", argv[optind + 1] );
  if ( num_args == 3 ) {
    desired_tcp_port = parse_port_number_or_exit( argv[0], "TCP", argv[optind + 2] );
  }

  /* Read key from environment */
  char* env_key = getenv( "MOSH_KEY" );
  if ( env_key == NULL ) {
    fputs( "MOSH_KEY environment variable not found.\n", stderr );
    exit( 1 );
  }

  /* Read prediction preference */
  char* predict_mode = getenv( "MOSH_PREDICTION_DISPLAY" );
  /* can be NULL */

  /* Read prediction insertion preference */
  char* predict_overwrite = getenv( "MOSH_PREDICTION_OVERWRITE" );
  /* can be NULL */

  /* Read transport mode preference */
  char* transport_mode_str = getenv( "MOSH_TRANSPORT_MODE" );
  /* can be NULL */

  Network::NetworkTransportMode transport_mode;
  if ( transport_mode_str == nullptr || strcmp( transport_mode_str, "UDP" ) == 0 ) {
    transport_mode = Network::NetworkTransportMode::UDP_ONLY;
  } else if ( strcmp( transport_mode_str, "TCP" ) == 0 ) {
    transport_mode = Network::NetworkTransportMode::TCP_ONLY;
  } else if ( strcmp( transport_mode_str, "PREFER_UDP" ) == 0 ) {
    transport_mode = Network::NetworkTransportMode::PREFER_UDP;
  } else {
    fprintf( stderr, "Invalid network transport mode\n" );
    exit( 1 );
  }

  std::string key( env_key );

  if ( unsetenv( "MOSH_KEY" ) < 0 ) {
    perror( "unsetenv" );
    exit( 1 );
  }

  /* Adopt native locale */
  set_native_locale();

  bool success = false;
  try {
    STMClient client(
      ip, desired_udp_port, desired_tcp_port, key, predict_mode, transport_mode, verbose, predict_overwrite );
    client.init();

    try {
      success = client.main();
    } catch ( ... ) {
      client.shutdown();
      throw;
    }

    client.shutdown();
  } catch ( const Network::NetworkException& e ) {
    fprintf( stderr, "Network exception: %s\r\n", e.what() );
    success = false;
  } catch ( const Crypto::CryptoException& e ) {
    fprintf( stderr, "Crypto exception: %s\r\n", e.what() );
    success = false;
  } catch ( const std::exception& e ) {
    fprintf( stderr, "Error: %s\r\n", e.what() );
    success = false;
  }

  printf( "[mosh is exiting.]\n" );

  return !success;
}
