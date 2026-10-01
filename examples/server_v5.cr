# An MQTT 5.0-only server. The IO is pinned before the first byte is read, so
# every packet is v5-framed, and the server can use what v5 adds: CONNACK
# properties, reason codes on every ack, and server-sent DISCONNECT.
#
#   crystal run examples/server_v5.cr
#   mosquitto_pub -V mqttv5 -t test -m hello -q 1
#
# Not a broker: it acknowledges what it receives and routes nothing.
require "socket"
require "../src/mqtt-protocol"

def handle(socket : TCPSocket) : Nil
  io = MQTT::Protocol::IO.v5(socket)
  connect = read_connect(io) || return

  if connect.properties.authentication_method
    # Enhanced authentication (AUTH packets) is not implemented here.
    return reject(io, MQTT::Protocol::Connack::ReasonCode::BadAuthenticationMethod)
  end

  properties = MQTT::Protocol::ConnackProperties.new
  properties.maximum_qos = 1u8
  properties.shared_subscription_available = false
  client_id = connect.client_id
  if client_id.empty?
    # v5 requires telling the client which id it was given [MQTT-3.2.2-16].
    client_id = "auto-#{Random::Secure.hex(8)}"
    properties.assigned_client_identifier = client_id
  end
  puts "#{client_id} connected"
  io.write_packet MQTT::Protocol::Connack.new(false, MQTT::Protocol::Connack::ReasonCode::Success, properties)
  io.flush
  serve(io)
ensure
  socket.close
end

# Read the CONNECT, or answer a bad one with a CONNACK and return nil.
def read_connect(io : MQTT::Protocol::IO) : MQTT::Protocol::Connect?
  io.read_connect
rescue ex : MQTT::Protocol::Error::Connect
  # Bad protocol name or level, rejected client id, ...
  reject(io, ex.reason_code)
rescue ex : MQTT::Protocol::Error::PacketDecode
  # Every decode error carries a v5 reason code. A 3.x CONNECT lands here
  # too, as a ProtocolError (0x82) from the pinned IO.
  reason = MQTT::Protocol::Connack::ReasonCode.from_value?(ex.reason_code)
  reject(io, reason || MQTT::Protocol::Connack::ReasonCode::UnspecifiedError)
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
      # Above the maximum_qos the CONNACK advertised: QoS Not Supported.
      return disconnect(io, MQTT::Protocol::Disconnect::ReasonCode::QosNotSupported) if packet.qos > 1
      puts "#{packet.topic}: #{String.new(packet.payload)}"
      if packet_id = packet.packet_id # QoS 1
        io.write_packet MQTT::Protocol::PubAck.new(packet_id)
      end
    when MQTT::Protocol::Subscribe
      codes = packet.topic_filters.map { |filter| suback_reason(filter) }
      io.write_packet MQTT::Protocol::SubAck.new(codes, packet.packet_id)
    when MQTT::Protocol::Unsubscribe
      # Nothing is ever subscribed here, so there is nothing to remove.
      codes = packet.topic_filters.map { MQTT::Protocol::UnsubAck::ReasonCode::NoSubscriptionExisted }
      io.write_packet MQTT::Protocol::UnsubAck.new(codes, packet.packet_id)
    when MQTT::Protocol::PingReq
      io.write_packet MQTT::Protocol::PingResp.new
    when MQTT::Protocol::Disconnect
      puts "client disconnected: #{packet.reason_code}"
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

def disconnect(io : MQTT::Protocol::IO, reason : MQTT::Protocol::Disconnect::ReasonCode) : Nil
  io.write_packet MQTT::Protocol::Disconnect.new(reason)
  io.flush
end

def suback_reason(filter : MQTT::Protocol::Subscribe::TopicFilter) : MQTT::Protocol::SubAck::ReasonCode
  if filter.topic.starts_with?("$share/")
    MQTT::Protocol::SubAck::ReasonCode::SharedSubscriptionsNotSupported
  elsif filter.qos.zero?
    MQTT::Protocol::SubAck::ReasonCode::GrantedQos0
  else
    MQTT::Protocol::SubAck::ReasonCode::GrantedQos1
  end
end

server = TCPServer.new("127.0.0.1", 1883)
puts "Listening on #{server.local_address}"
while socket = server.accept?
  spawn handle(socket)
end
