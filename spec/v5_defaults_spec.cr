require "./spec_helper"

# A consumer reads every packet in v5 terms: an absent property reads as its
# MQTT 5 default, and a v3 packet (which has no properties at all) reads as the
# v5 packet that means the same thing.

private def decode(bytes : Bytes, version) : MQTT::Protocol::Packet
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO.for(version, mio))
end

private def encode(packet, version) : Bytes
  mio = IO::Memory.new
  packet.to_io(MQTT::Protocol::IO.for(version, mio))
  mio.to_slice
end

# 0x10 | rem_len 15 | "MQTT" | level 4 | flags | keepalive 60 | client id "cid"
private def v3_connect_bytes(flags : UInt8) : Bytes
  Bytes[0x10, 0x0F, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04,
    flags, 0x00, 0x3C, 0x00, 0x03, 0x63, 0x69, 0x64]
end

private def v3_connect(clean_start : Bool, properties = MQTT::Protocol::ConnectProperties.new)
  MQTT::Protocol::Connect.new("cid", clean_start: clean_start, keep_alive: 60u16,
    version: MQTT::Protocol::Version::V3_1_1, properties: properties)
end

describe "property defaults" do
  it "reads an absent property as its MQTT 5 default" do
    connect = MQTT::Protocol::ConnectProperties.new
    connect.session_expiry_interval.should eq 0u32
    connect.receive_maximum.should eq 65535u16
    connect.topic_alias_maximum.should eq 0u16
    connect.request_response_information?.should be_false
    connect.request_problem_information?.should be_true

    connack = MQTT::Protocol::ConnackProperties.new
    connack.receive_maximum.should eq 65535u16
    connack.maximum_qos.should eq 2u8
    connack.retain_available?.should be_true
    connack.topic_alias_maximum.should eq 0u16
    connack.wildcard_subscription_available?.should be_true
    connack.subscription_identifier_available?.should be_true
    connack.shared_subscription_available?.should be_true

    will = MQTT::Protocol::WillProperties.new
    will.will_delay_interval.should eq 0u32
    will.payload_format_indicator?.should be_false

    MQTT::Protocol::PublishProperties.new.payload_format_indicator?.should be_false
  end

  it "keeps nil where absent has no single value" do
    MQTT::Protocol::ConnectProperties.new.maximum_packet_size.should be_nil
    MQTT::Protocol::ConnackProperties.new.server_keep_alive.should be_nil
    MQTT::Protocol::ConnackProperties.new.session_expiry_interval.should be_nil
    MQTT::Protocol::DisconnectProperties.new.session_expiry_interval.should be_nil
    MQTT::Protocol::PublishProperties.new.message_expiry_interval.should be_nil
  end

  it "reads a set value over the default, including false over a true default" do
    props = MQTT::Protocol::ConnackProperties.new(maximum_qos: 0u8, retain_available: false)
    props.maximum_qos.should eq 0u8
    props.retain_available?.should be_false
  end

  it "tells absent from set through the ? reader of an integer property" do
    MQTT::Protocol::ConnectProperties.new.receive_maximum?.should be_nil
    MQTT::Protocol::ConnectProperties.new(receive_maximum: 65535u16).receive_maximum?.should eq 65535u16
  end

  it "does not put a default on the wire" do
    MQTT::Protocol::ConnackProperties.new.empty?.should be_true
  end
end

describe "a v3 CONNECT in v5 terms" do
  it "reads Clean Session 0 as Clean Start 0 with a session that never expires" do
    connect = decode(v3_connect_bytes(0x00), MQTT::Protocol::Version::V3_1_1).as(MQTT::Protocol::Connect)
    connect.clean_start?.should be_false
    connect.properties.session_expiry_interval.should eq UInt32::MAX
  end

  it "reads Clean Session 1 as Clean Start 1 with a session that ends at disconnect" do
    connect = decode(v3_connect_bytes(0x02), MQTT::Protocol::Version::V3_1_1).as(MQTT::Protocol::Connect)
    connect.clean_start?.should be_true
    connect.properties.session_expiry_interval.should eq 0u32
  end

  it "decodes equal to the same CONNECT constructed" do
    bytes = v3_connect_bytes(0x00)
    decode(bytes, MQTT::Protocol::Version::V3_1_1).should eq v3_connect(clean_start: false)
    encode(v3_connect(clean_start: false), MQTT::Protocol::Version::V3_1_1).should eq bytes
  end

  it "keeps a session expiry that was set explicitly" do
    props = MQTT::Protocol::ConnectProperties.new(session_expiry_interval: 30u32)
    v3_connect(false, props).properties.session_expiry_interval.should eq 30u32
  end

  it "leaves a v5 CONNECT's session expiry to the wire" do
    connect = MQTT::Protocol::Connect.new("cid", clean_start: false, version: MQTT::Protocol::Version::V5)
    connect.properties.session_expiry_interval?.should be_nil
  end
end

describe "a v3 CONNACK in v5 terms" do
  it "reads subscription identifiers and shared subscriptions as unavailable" do
    connack = decode(Bytes[0x20, 0x02, 0x00, 0x00], MQTT::Protocol::Version::V3_1_1).as(MQTT::Protocol::Connack)
    connack.properties.subscription_identifier_available?.should be_false
    connack.properties.shared_subscription_available?.should be_false
    connack.properties.wildcard_subscription_available?.should be_true
    connack.properties.retain_available?.should be_true
    connack.properties.maximum_qos.should eq 2u8
  end

  it "differs from a v5 CONNACK without properties" do
    connack = decode(Bytes[0x20, 0x03, 0x00, 0x00, 0x00], MQTT::Protocol::Version::V5).as(MQTT::Protocol::Connack)
    connack.properties.subscription_identifier_available?.should be_true
    connack.properties.shared_subscription_available?.should be_true
  end
end
