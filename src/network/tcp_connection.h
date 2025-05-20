#ifndef MOSH_TCP_CONNECTION_H
#define MOSH_TCP_CONNECTION_H

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
  class Packet
  {
  public:
    const uint64_t seq;
    Direction direction;
    std::string payload;

    Packet( Direction s_direction, uint64_t s_seq, const std::string& s_payload )
      : seq( s_seq ), direction( s_direction ), payload( s_payload )
    {}

    Packet( Message message );
    Message toMessage( void );
  };

  using packet_len_t = uint32_t;
  static const packet_len_t MAX_PACKET_LEN = UINT32_MAX;
  bool verbose = false;

  struct TCPStream
  {
    uint32_t stream_id; // For logging
    Addr remote_addr;
    uint64_t expecting_seq_number = 0;

    Socket sock;
    bool is_connected = false;
    bool dead = false;

    double srtt = 1000;
    uint32_t last_heard_ms = 0;
    uint32_t timeout = 0;

    packet_len_t rcv_current_packet_len = 0;
    packet_len_t rcv_index = 0;
    std::string rcv_buf {};

    std::string send_buffer {};
    std::string::size_type send_buffer_index = 0;

    std::string error {};

    struct
    {
      uint64_t old_num = 0;
      uint64_t new_num = 0;
      uint64_t ack_num = 0;
      uint64_t throwaway_num = 0;

      bool has_sent( const Instruction& inst )
      {
        return inst.old_num() == old_num && inst.new_num() == new_num && inst.ack_num() == ack_num
               && inst.throwaway_num() == throwaway_num;
      }

      void update( const Instruction& inst )
      {
        old_num = inst.old_num();
        new_num = inst.new_num();
        ack_num = inst.ack_num();
        throwaway_num = inst.throwaway_num();
      }
    } last_instr;

    TCPStream( uint32_t stream_id, Addr remote_addr, Socket&& sock, bool is_connected )
      : stream_id( stream_id ), remote_addr( remote_addr ), sock( std::move( sock ) ), is_connected( is_connected )
    {
      assert( stream_id != 0 );
    }

    void check_if_connected( void );

    bool fill_rcv_buf( size_t size );
    std::optional<std::string_view> recv_bytes( void );

    std::optional<packet_len_t> send( const std::string& data );
    std::optional<packet_len_t> send_bytes( const std::string& data, packet_len_t index );
    bool finish_send( void );

    void update_conn_stats( void );
  };

  static constexpr unsigned int MAX_STREAMS = 3;

  ReportFunction report_fn {};

  Session session;
  Counter seq_counter {};
  Direction direction;
  std::string error {};

  bool enabled = true;
  uint64_t last_connect_attempt = 0;
  uint32_t last_stream_id = 0;

  std::optional<Socket> server_socket {};
  Addr server_addr {};
  std::deque<TCPStream> streams;

  bool is_server() const { return server_socket.has_value(); }
  Packet new_packet( const std::string& s_payload );

  bool connect( const Addr& addr );
  // returns the new stream's id
  uint32_t accept( void );

  void send_dropped( uint32_t stream_id, const TransportBuffers::Instruction& inst );
  void prune_streams();

public:
  TCPConnection( Crypto::Base64Key key, const char* desired_ip, PortRange desired_udp_port );
  TCPConnection( Crypto::Base64Key key, const char* addr, Port port );

  void set_report_function( ReportFunction report_fn ) override { this->report_fn = std::move( report_fn ); }

  void send( const TransportBuffers::Instruction& inst ) override;
  std::string clear_send_error( void ) override;

  std::optional<Instruction> recv( void ) override;

  virtual void register_select( Select& select ) override;
  virtual Actions wakeup( Select& select ) override;

  std::optional<Port> udp_port( void ) const override { return std::nullopt; };
  std::optional<Port> tcp_port( void ) const override;

  uint64_t get_RTO( void ) const override;
  double get_SRTT( void ) const override;

  const Addr* get_remote_addr( void ) const override;
  bool has_remote_addr( void ) const override;

  void set_last_roundtrip_success( uint64_t timestamp ) override {};

  void enable() { enabled = true; };

  void disable()
  {
    enabled = false;
    streams.clear();
  }

  bool is_enabled() { return enabled; }

  void set_verbose( bool verbose ) override { this->verbose = verbose; }
};

}
#endif