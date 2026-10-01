# An MQTT 3.1.1-only server. The IO is pinned before the first byte is read,
# so every packet, including a CONNACK rejecting a bad CONNECT, is v3-framed.
# To accept both v3 flavours (3.1 MQIsdp and 3.1.1), see server_auto_version.cr.
#
#   crystal run examples/server_v3.cr
#   mosquitto_pub -V mqttv311 -t test -m hello -q 1
#
# Not a broker: it acknowledges what it receives and routes nothing.
require "socket"
require "../src/mqtt-protocol"

def handle(socket : TCPSocket) : Nil
  # For MQTT 3.1, pass version: MQTT::Protocol::Version::V3_1.
  io = MQTT::Protocol::IO.v3(socket)
  connect = read_connect(io) || return
  puts "#{connect.client_id} connected"

  io.write_packet MQTT::Protocol::Connack.new(false, MQTT::Protocol::Connack::ReasonCode::Success)
  io.flush
  serve(io)
ensure
  socket.close
end

# Read the CONNECT, or answer a bad one with a CONNACK and return nil.
def read_connect(io : MQTT::Protocol::IO) : MQTT::Protocol::Connect?
  io.read_connect
rescue ex : MQTT::Protocol::Error::Connect
  # Bad protocol name or level, rejected client id, ...: v3 has a return code.
  reject(io, ex.reason_code)
rescue MQTT::Protocol::Error::PacketDecode
  # Malformed, or a CONNECT for another version (a ProtocolError on a pinned
  # IO). v3 has no CONNACK code for either, so just close.
rescue IO::Error
end

def reject(io : MQTT::Protocol::IO, reason : MQTT::Protocol::Connack::ReasonCode) : Nil
  io.write_packet MQTT::Protocol::Connack.new(false, reason)
  io.flush
end

# A v3 server cannot send DISCONNECT: on any protocol violation it just closes.
def serve(io : MQTT::Protocol::IO) : Nil
  loop do
    case packet = io.read_packet
    when MQTT::Protocol::Publish
      return if packet.qos > 1 # no QoS 2 flow here
      puts "#{packet.topic}: #{String.new(packet.payload)}"
      if packet_id = packet.packet_id # QoS 1
        io.write_packet MQTT::Protocol::PubAck.new(packet_id)
      end
    when MQTT::Protocol::Subscribe
      codes = packet.topic_filters.map { |filter| suback_reason(filter) }
      io.write_packet MQTT::Protocol::SubAck.new(codes, packet.packet_id)
    when MQTT::Protocol::Unsubscribe
      io.write_packet MQTT::Protocol::UnsubAck.new([] of MQTT::Protocol::UnsubAck::ReasonCode, packet.packet_id)
    when MQTT::Protocol::PingReq
      io.write_packet MQTT::Protocol::PingResp.new
    when MQTT::Protocol::Disconnect
      return
    else
      # Includes a second CONNECT [MQTT-3.1.0-2], which the library leaves to us.
      return
    end
    io.flush
  end
rescue MQTT::Protocol::Error::PacketDecode | IO::Error
end

def suback_reason(filter : MQTT::Protocol::Subscribe::TopicFilter) : MQTT::Protocol::SubAck::ReasonCode
  filter.qos.zero? ? MQTT::Protocol::SubAck::ReasonCode::GrantedQoS0 : MQTT::Protocol::SubAck::ReasonCode::GrantedQoS1
end

server = TCPServer.new("127.0.0.1", 1883)
puts "Listening on #{server.local_address}"
while socket = server.accept?
  spawn handle(socket)
end
