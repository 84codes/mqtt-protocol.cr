require "./spec_helper"

# Property value constraints (FABLE_FINDINGS.md 2.3): MQTT 5.0 declares a
# Protocol Error for out-of-range property values. A constraint is declared as
# the `range:` on the property's `prop` in properties.cr, so every packet
# type that has the property enforces it in the generated decoder.
private def decode_props(klass, bytes : Bytes)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  io = MQTT::Protocol::IO.v5(mio)
  klass.from_io(io, bytes.size.to_u32)
end

private def expect_out_of_range(klass, bytes : Bytes)
  ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { decode_props(klass, bytes) }
  ex.reason_code.should eq 0x82u8
end

describe "v5 property value constraints" do
  it "rejects a boolean property with a value other than 0 or 1" do
    # Request Response Information (0x19) = 2; 3.1.2.11.6: "It is a Protocol
    # Error ... to have a value other than 0 or 1".
    expect_out_of_range MQTT::Protocol::ConnectProperties, Bytes[0x02, 0x19, 0x02]
  end

  it "rejects Maximum QoS above 1" do
    # 3.2.2.3.4: Maximum QoS (0x24) with a value other than 0 or 1 is a
    # Protocol Error.
    expect_out_of_range MQTT::Protocol::ConnackProperties, Bytes[0x02, 0x24, 0x02]
  end

  it "rejects Topic Alias 0" do
    # 3.3.2.3.4: a Topic Alias (0x23) of 0 is a Protocol Error.
    expect_out_of_range MQTT::Protocol::PublishProperties, Bytes[0x03, 0x23, 0x00, 0x00]
  end

  it "rejects Receive Maximum 0" do
    # 3.1.2.11.3 / 3.2.2.3.3: Receive Maximum (0x21) value 0 is a Protocol Error.
    expect_out_of_range MQTT::Protocol::ConnectProperties, Bytes[0x03, 0x21, 0x00, 0x00]
    expect_out_of_range MQTT::Protocol::ConnackProperties, Bytes[0x03, 0x21, 0x00, 0x00]
  end

  it "rejects Maximum Packet Size 0" do
    # 3.1.2.11.4 / 3.2.2.3.6: Maximum Packet Size (0x27) value 0 is a Protocol Error.
    expect_out_of_range MQTT::Protocol::ConnectProperties, Bytes[0x05, 0x27, 0x00, 0x00, 0x00, 0x00]
  end

  it "rejects a repeated Subscription Identifier of 0" do
    # 3.3.2.3.8: a Subscription Identifier has the range 1..268,435,455, so a
    # repeated one of 0 is a Protocol Error just like the single SUBSCRIBE form
    # (3.8.2.1.2).
    expect_out_of_range MQTT::Protocol::PublishProperties, Bytes[0x02, 0x0B, 0x00]
  end

  it "still accepts in-range values" do
    props = decode_props(MQTT::Protocol::ConnackProperties, Bytes[0x02, 0x24, 0x01])
    props.maximum_qos.should eq 1u8
    props = decode_props(MQTT::Protocol::PublishProperties, Bytes[0x03, 0x23, 0x00, 0x01])
    props.topic_alias.should eq 1u16
  end
end

# 1.8: a v5 PUBLISH with a zero-length Topic Name is only legal when a Topic
# Alias is present (the unnumbered Protocol Error sentence in 3.3.2.1); the encode side must not emit
# an empty topic it could never emit legally.
private def decode_v5(bytes : Bytes)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO.v5(mio))
end

describe "v5 PUBLISH empty topic" do
  it "rejects an empty topic without a Topic Alias" do
    # rem_len 4: topic (00 00) + empty props (00) + 1 payload byte.
    bytes = Bytes[0x30, 0x04, 0x00, 0x00, 0x00, 0x61]
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { decode_v5(bytes) }
    ex.reason_code.should eq 0x82u8
  end

  it "accepts an empty topic with a Topic Alias" do
    # rem_len 7: topic (00 00) + props (03: 0x23 alias 5) + 1 payload byte.
    bytes = Bytes[0x30, 0x07, 0x00, 0x00, 0x03, 0x23, 0x00, 0x05, 0x61]
    packet = decode_v5(bytes).as(MQTT::Protocol::Publish)
    packet.topic_bytes.empty?.should be_true
    packet.properties.topic_alias.should eq 5u16
  end

  it "refuses to encode an empty topic on a v3 connection" do
    packet = MQTT::Protocol::Publish.new("", "x".to_slice)
    io = MQTT::Protocol::IO.v3(IO::Memory.new)
    expect_raises(MQTT::Protocol::Error::PacketEncode) { io.write_packet(packet) }
  end

  it "refuses to encode an empty topic on v5 without a Topic Alias" do
    packet = MQTT::Protocol::Publish.new("", "x".to_slice)
    io = MQTT::Protocol::IO.v5(IO::Memory.new)
    expect_raises(MQTT::Protocol::Error::PacketEncode) { io.write_packet(packet) }
  end

  it "encodes an empty topic on v5 with a Topic Alias" do
    props = MQTT::Protocol::PublishProperties.new(topic_alias: 5u16)
    packet = MQTT::Protocol::Publish.new("", "x".to_slice, properties: props)
    mio = IO::Memory.new
    MQTT::Protocol::IO.v5(mio).write_packet(packet)
    mio.rewind
    decoded = MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO.v5(mio)).as(MQTT::Protocol::Publish)
    decoded.properties.topic_alias.should eq 5u16
  end
end

# 5.2: the declared ranges must also hold on encode - the shard must never
# construct a packet its own decoder rejects. Constructor and setter enforce
# the same range table; out-of-range construction is an ArgumentError.
describe "property value constraints on construction" do
  it "rejects Maximum QoS above 1 in the constructor" do
    expect_raises(ArgumentError, /maximum_qos/) do
      MQTT::Protocol::ConnackProperties.new(maximum_qos: 2u8)
    end
  end

  it "rejects Maximum QoS above 1 via the setter" do
    props = MQTT::Protocol::ConnackProperties.new
    expect_raises(ArgumentError, /maximum_qos/) { props.maximum_qos = 2u8 }
  end

  it "rejects Topic Alias 0 (which would defeat the empty-topic gate)" do
    expect_raises(ArgumentError, /topic_alias/) do
      MQTT::Protocol::PublishProperties.new(topic_alias: 0u16)
    end
  end

  it "rejects Receive Maximum 0 in constructor and setter" do
    expect_raises(ArgumentError, /receive_maximum/) do
      MQTT::Protocol::ConnectProperties.new(receive_maximum: 0u16)
    end
    props = MQTT::Protocol::ConnackProperties.new
    expect_raises(ArgumentError, /receive_maximum/) { props.receive_maximum = 0u16 }
  end

  it "rejects Maximum Packet Size 0 in the constructor" do
    expect_raises(ArgumentError, /maximum_packet_size/) do
      MQTT::Protocol::ConnectProperties.new(maximum_packet_size: 0u32)
    end
  end

  it "rejects Subscription Identifier 0 in the constructor" do
    expect_raises(ArgumentError, /subscription_identifier/) do
      MQTT::Protocol::SubscribeProperties.new(subscription_identifier: 0u32)
    end
  end

  it "rejects Subscription Identifier 0 in the repeatable list" do
    # The range applies to every element, so a PUBLISH cannot be built with a
    # list its own decoder would reject.
    expect_raises(ArgumentError, /subscription_identifiers/) do
      MQTT::Protocol::PublishProperties.new(subscription_identifiers: [1u32, 0u32])
    end
    props = MQTT::Protocol::PublishProperties.new
    expect_raises(ArgumentError, /subscription_identifiers/) do
      props.subscription_identifiers = [0u32]
    end
  end

  it "accepts in-range and nil values" do
    props = MQTT::Protocol::ConnackProperties.new(maximum_qos: 1u8, receive_maximum: 1u16)
    props.maximum_qos.should eq 1u8
    props.maximum_qos = nil
    props.maximum_qos?.should be_nil
    MQTT::Protocol::PublishProperties.new(topic_alias: 65535u16).topic_alias.should eq 65535u16
  end
end
