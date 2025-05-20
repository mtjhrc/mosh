#ifndef MOSH_CONNECTION_HPP
#define MOSH_CONNECTION_HPP

#include "src/network/network.h"
#include "src/protobufs/transportinstruction.pb.h"
#include "src/util/select.h"
#include "transportfragment.h"
#include <functional>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace Network {

struct TcpRecvReport
{
  uint32_t stream_id;
  const TransportBuffers::Instruction& inst;
};

struct UdpRecvReport
{
  const TransportBuffers::Instruction& inst;
};

struct TcpSendDroppedReport
{
  uint32_t stream_id;
  const TransportBuffers::Instruction& inst;
  uint64_t timeout;
  double srtt;
};

struct TcpSendReport
{
  uint32_t stream_id;
  const TransportBuffers::Instruction& inst;
  uint32_t sent_len;
  uint32_t msg_len;
  uint64_t timeout;
  double srtt;
};

struct UdpSendReport
{
  const TransportBuffers::Instruction& inst;
  const Fragment& fragment;
  uint64_t timeout;
  double srtt;
};

struct TransportChangedReport;

struct Actions
{
  bool recv = false;
};

class Connection
{
public:
  using ReportFunction = std::function<void( const std::variant<UdpRecvReport,
                                                                TcpRecvReport,
                                                                TcpSendReport,
                                                                UdpSendReport,
                                                                TcpSendDroppedReport,
                                                                TransportChangedReport>& )>;

  enum class Transport : uint8_t
  {
    UDP,
    TCP,
    BOTH,
  };

  static const char* transport_name( Transport transport )
  {
    switch ( transport ) {
      case Transport::UDP:
        return "UDP";
      case Transport::TCP:
        return "TCP";
      case Transport::BOTH:
        return "BOTH";
      default:
        throw std::runtime_error( "Invalid Transport: " + std::to_string( static_cast<uint8_t>( transport ) ) );
    }
  }

  virtual ~Connection() {};
  virtual void set_report_function( ReportFunction report_fn ) = 0;

  virtual void send( const TransportBuffers::Instruction& inst ) = 0;
  virtual std::string clear_send_error( void ) = 0;

  virtual std::optional<TransportBuffers::Instruction> recv( void ) = 0;

  // Register fds to monitor
  virtual void register_select( Select& select ) = 0;
  // Check if Select contains any events of interest to this Connection
  // Returns which actions need to be performed be the caller
  virtual Actions wakeup( Select& select ) = 0;

  virtual std::optional<Port> udp_port( void ) const = 0;
  virtual std::optional<Port> tcp_port( void ) const = 0;

  // Retransmission timeout
  virtual uint64_t get_RTO( void ) const = 0;
  // Smoothed round-trip time
  virtual double get_SRTT( void ) const = 0;

  virtual const Addr* get_remote_addr( void ) const = 0;
  virtual bool has_remote_addr( void ) const { return get_remote_addr() != nullptr; };

  virtual void set_last_roundtrip_success( uint64_t timestamp ) = 0;
  virtual void set_verbose( bool verbose ) {}
};

struct TransportChangedReport
{
  Connection::Transport from;
  Connection::Transport to;
};

}

#endif // MOSH_CONNECTION_HPP