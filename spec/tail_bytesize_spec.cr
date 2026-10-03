require "./spec_helper"

# Drift guard for the v5 tail-omission rule (3.4.2.1 / 3.14.2.1): a zero
# (success) reason with no properties omits the tail entirely; a bare reason
# omits the properties section. The rule feeds both `remaining_length` (what
# the packet reports) and the writers (what actually goes on the wire); these
# specs pin that the two never drift apart, for every tail shape.
private def written_size(packet, version = MQTT::Protocol::Version::V5) : UInt32
  mio = IO::Memory.new
  io = MQTT::Protocol::IO.for(version, mio)
  io.write_packet(packet)
  mio.size.to_u32
end

private def assert_bytesize_matches_wire(packet, version = MQTT::Protocol::Version::V5)
  io = MQTT::Protocol::IO.for(version, IO::Memory.new)
  io.bytesize(packet).should eq written_size(packet, version)
end

describe "v5 tail bytesize matches wire" do
  props = MQTT::Protocol::PubAckProperties.new(reason_string: "why")

  it "for acks: success + no properties (omitted tail)" do
    assert_bytesize_matches_wire MQTT::Protocol::PubAck.new(1u16)
  end

  it "for acks: reason + no properties (bare reason byte)" do
    packet = MQTT::Protocol::PubAck.new(1u16, MQTT::Protocol::PubAck::ReasonCode::QuotaExceeded)
    assert_bytesize_matches_wire packet
  end

  it "for acks: reason + properties (full tail)" do
    packet = MQTT::Protocol::PubAck.new(1u16, MQTT::Protocol::PubAck::ReasonCode::QuotaExceeded, props)
    assert_bytesize_matches_wire packet
  end

  it "for acks: success reason but non-empty properties (tail must not be omitted)" do
    assert_bytesize_matches_wire MQTT::Protocol::PubAck.new(1u16, properties: props)
  end

  it "for DISCONNECT: all tail shapes" do
    dprops = MQTT::Protocol::DisconnectProperties.new(reason_string: "bye")
    assert_bytesize_matches_wire MQTT::Protocol::Disconnect.new
    assert_bytesize_matches_wire MQTT::Protocol::Disconnect.new(MQTT::Protocol::Disconnect::ReasonCode::ServerBusy)
    assert_bytesize_matches_wire MQTT::Protocol::Disconnect.new(MQTT::Protocol::Disconnect::ReasonCode::ServerBusy, dprops)
    assert_bytesize_matches_wire MQTT::Protocol::Disconnect.new(properties: dprops)
  end

  it "for AUTH: all tail shapes" do
    aprops = MQTT::Protocol::AuthProperties.new(authentication_method: "SCRAM-SHA-1")
    assert_bytesize_matches_wire MQTT::Protocol::Auth.new
    assert_bytesize_matches_wire MQTT::Protocol::Auth.new(MQTT::Protocol::Auth::ReasonCode::ContinueAuthentication)
    assert_bytesize_matches_wire MQTT::Protocol::Auth.new(MQTT::Protocol::Auth::ReasonCode::ContinueAuthentication, aprops)
    assert_bytesize_matches_wire MQTT::Protocol::Auth.new(properties: aprops)
  end

  it "for v3 acks and DISCONNECT (no tail ever)" do
    assert_bytesize_matches_wire MQTT::Protocol::PubAck.new(1u16, properties: props), MQTT::Protocol::Version::V3_1_1
    assert_bytesize_matches_wire MQTT::Protocol::Disconnect.new, MQTT::Protocol::Version::V3_1_1
  end
end
