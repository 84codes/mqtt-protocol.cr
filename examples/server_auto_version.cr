# An MQTT server that takes each client's protocol version from its CONNECT,
# so one listener serves 3.1, 3.1.1 and 5.0 clients. Packets are built the v5
# way everywhere; the IO frames them for whichever version was negotiated.
#
#   crystal run examples/server_auto_version.cr
#   mosquitto_pub -V mqttv311 -t test -m hello -q 1
#   mosquitto_pub -V mqttv5 -t test -m hello -q 1
#
# Not a broker: it acknowledges what it receives and routes nothing.
require "socket"
require "../src/mqtt-protocol"

def handle(socket : TCPSocket) : Nil
  # No version yet: io.version is Unknown and only a CONNECT can be read.
  io = MQTT::Protocol::IO.new(socket)
  connect = read_connect(io) || return
  puts "#{connect.client_id} connected with #{io.version}"

  properties = MQTT::Protocol::ConnackProperties.new
  properties.maximum_qos = 1u8 # sent to v5 clients, dropped by v3 framing
  io.write_packet MQTT::Protocol::Connack.new(false, MQTT::Protocol::Connack::ReasonCode::Success, properties)
  io.flush
  serve(io)
ensure
  socket.close
end

# Read the CONNECT, or answer a bad one with a CONNACK and return nil. The IO
# keeps whatever version the CONNECT got as far as announcing, so the CONNACK
# is framed for the client's version, or v3 if it never got that far.
def read_connect(io : MQTT::Protocol::IO) : MQTT::Protocol::Connect?
  io.read_connect
rescue ex : MQTT::Protocol::Error::Connect
  # Bad protocol name or level, rejected client id, ...: every version has a code.
  reject(io, ex.reason_code)
rescue ex : MQTT::Protocol::Error::PacketDecode
  # Only v5 has CONNACK codes for a malformed CONNECT; v3 just closes.
  if io.version.v5? && (reason = MQTT::Protocol::Connack::ReasonCode.from_value?(ex.reason_code))
    reject(io, reason)
  end
rescue IO::Error
end

def reject(io : MQTT::Protocol::IO, reason : MQTT::Protocol::Connack::ReasonCode) : Nil
  io.write_packet MQTT::Protocol::Connack.new(false, reason)
  io.flush
end

def serve(io : MQTT::Protocol::IO) : Nil
  loop do
    case packet = io.read_packet
    when MQTT::Protocol::Publish
      # No QoS 2 flow here; v5 clients were told so by maximum_qos.
      return disconnect(io, MQTT::Protocol::Disconnect::ReasonCode::QoSNotSupported) if packet.qos > 1
      puts "#{packet.topic}: #{String.new(packet.payload)}"
      if packet_id = packet.packet_id # QoS 1
        io.write_packet MQTT::Protocol::PubAck.new(packet_id)
      end
    when MQTT::Protocol::Subscribe
      codes = packet.topic_filters.map { |filter| suback_reason(filter) }
      io.write_packet MQTT::Protocol::SubAck.new(codes, packet.packet_id)
    when MQTT::Protocol::Unsubscribe
      # v3 framing drops the per-topic reason codes.
      codes = packet.topics.map { MQTT::Protocol::UnsubAck::ReasonCode::Success }
      io.write_packet MQTT::Protocol::UnsubAck.new(packet.packet_id, codes)
    when MQTT::Protocol::PingReq
      io.write_packet MQTT::Protocol::PingResp.new
    when MQTT::Protocol::Disconnect
      return
    else
      # Includes a second CONNECT [MQTT-3.1.0-2], which the library leaves to us.
      return disconnect(io, MQTT::Protocol::Disconnect::ReasonCode::ProtocolError)
    end
    io.flush
  end
rescue ex : MQTT::Protocol::Error::PacketDecode
  reason = MQTT::Protocol::Disconnect::ReasonCode.from_value?(ex.reason_code)
  disconnect(io, reason || MQTT::Protocol::Disconnect::ReasonCode::UnspecifiedError)
rescue IO::Error
end

# Only a v5 server may send DISCONNECT; on v3 the server just closes.
def disconnect(io : MQTT::Protocol::IO, reason : MQTT::Protocol::Disconnect::ReasonCode) : Nil
  return unless io.version.v5?
  io.write_packet MQTT::Protocol::Disconnect.new(reason)
  io.flush
end

def suback_reason(filter : MQTT::Protocol::Subscribe::TopicFilter) : MQTT::Protocol::SubAck::ReasonCode
  filter.qos.zero? ? MQTT::Protocol::SubAck::ReasonCode::GrantedQoS0 : MQTT::Protocol::SubAck::ReasonCode::GrantedQoS1
end

server = TCPServer.new("127.0.0.1", 1883)
puts "Listening on #{server.local_address}"
while socket = server.accept?
  spawn handle(socket)
end
