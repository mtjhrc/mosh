#ifndef MOSH_CONNECTION_HPP
#define MOSH_CONNECTION_HPP

#include "src/network/network.h"
#include "src/protobufs/transportinstruction.pb.h"
#include "transportfragment.h"
#include <functional>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace Network {

struct TcpRecvReport
{
  const TransportBuffers::Instruction& inst;
};

struct UdpRecvReport
{
  const TransportBuffers::Instruction& inst;
};

struct TcpSendDroppedReport
{
  const TransportBuffers::Instruction& inst;
  uint64_t timeout;
  double srtt;
};

struct TcpSendReport
{
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

class Connection
{
public:
  using ReportFunction = std::function<void(
    const std::variant<UdpRecvReport, TcpRecvReport, TcpSendReport, UdpSendReport, TcpSendDroppedReport>& )>;

  virtual ~Connection() {};

  virtual void set_report_function( ReportFunction report_fn ) = 0;

  virtual void send( const TransportBuffers::Instruction& inst ) = 0;
  virtual std::string clear_send_error( void ) = 0;
  virtual bool finish_send( void ) = 0;

  virtual std::optional<TransportBuffers::Instruction> recv( void ) = 0;

  virtual std::vector<int> fds_notify_read( void ) const = 0;
  virtual std::vector<int> fds_notify_write( void ) const = 0;

  virtual std::optional<Port> udp_port( void ) const = 0;
  virtual std::optional<Port> tcp_port( void ) const = 0;

  virtual uint64_t timeout( void ) const = 0;
  virtual double get_SRTT( void ) const = 0;

  virtual const Addr* get_remote_addr( void ) const = 0;
  virtual bool has_remote_addr( void ) const { return get_remote_addr() != nullptr; };

  virtual void set_last_roundtrip_success( uint64_t timestamp ) = 0;
};
}

#endif // MOSH_CONNECTION_HPP