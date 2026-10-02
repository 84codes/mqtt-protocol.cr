require "./spec_helper"

# SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK at v5 (MQTT5_FINDINGS.md section 4).
#
# SUBSCRIBE gains a properties section (subscription identifier, user property)
# and per-filter subscription options (No Local, Retain As Published, Retain
# Handling) packed into the options byte alongside the requested QoS.
#
# SUBACK/UNSUBACK gain a properties section; UNSUBACK additionally gains a
# per-filter reason-code payload that did not exist in v3.

private def encode_v5(packet)
  mio = IO::Memory.new
  io = MQTT::Protocol::IO::V5.new(mio)
  packet.to_io(io)
  mio.to_slice
end

private def decode_v5(bytes : Bytes)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  io = MQTT::Protocol::IO::V5.new(mio)
  MQTT::Protocol::Packet.from_io(io)
end

describe MQTT::Protocol::Subscribe do
  it "encodes a v5 SUBSCRIBE with empty properties and one QoS1 filter" do
    subscribe = MQTT::Protocol::Subscribe.new(
      topic_filters: [MQTT::Protocol::Subscribe::TopicFilter.new("a/b", 1u8)],
      packet_id: 1u16,
    )
    # 0x82, rem_len 9, packet id(00 01), props(00), filter(00 03 a / b) opts(01)
    encode_v5(subscribe).should eq Bytes[
      0x82, 0x09,
      0x00, 0x01,
      0x00,
      0x00, 0x03, 'a'.ord, '/'.ord, 'b'.ord,
      0x01,
    ]
  end

  it "packs subscription options (NL, RAP, RH) into the options byte" do
    filter = MQTT::Protocol::Subscribe::TopicFilter.new(
      topic: "x",
      qos: 2u8,
      no_local: true,
      retain_as_published: true,
      retain_handling: 1u8,
    )
    subscribe = MQTT::Protocol::Subscribe.new(topic_filters: [filter], packet_id: 1u16)
    bytes = encode_v5(subscribe)
    # options byte: qos2(0b10) | NL(0b100) | RAP(0b1000) | RH=1(0b01_0000) = 0x1E
    bytes[-1].should eq 0x1E

    decoded = decode_v5(bytes).as(MQTT::Protocol::Subscribe)
    f = decoded.topic_filters.first
    f.qos.should eq 2u8
    f.no_local?.should be_true
    f.retain_as_published?.should be_true
    f.retain_handling.should eq 1u8
  end

  it "round-trips SUBSCRIBE properties" do
    subscribe = MQTT::Protocol::Subscribe.new(
      topic_filters: [MQTT::Protocol::Subscribe::TopicFilter.new("a/#", 0u8)],
      packet_id: 7u16,
      properties: MQTT::Protocol::SubscribeProperties.new(
        subscription_identifier: 42u32,
        user_properties: [{"a", "b"}],
      ),
    )
    decoded = decode_v5(encode_v5(subscribe)).as(MQTT::Protocol::Subscribe)
    decoded.properties.subscription_identifier.should eq 42u32
    decoded.properties.user_properties.should eq [{"a", "b"}]
  end

  it "reports a bytesize matching the v5 serialization" do
    subscribe = MQTT::Protocol::Subscribe.new(
      topic_filters: [MQTT::Protocol::Subscribe::TopicFilter.new("a/b", 1u8)],
      packet_id: 1u16,
      properties: MQTT::Protocol::SubscribeProperties.new(subscription_identifier: 42u32),
    )
    subscribe.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(subscribe).size
  end

  it "raises PacketDecode when the properties length overruns remaining bytes" do
    # rem_len 4: packet id (2) leaves 1 byte; property length VBI claims 127.
    bytes = Bytes[0x82, 0x04, 0x00, 0x01, 0x7F]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end

  it "rejects reserved subscription-option bits 6-7 [MQTT-3.8.3-5]" do
    # filter "a/b", options 0x40 (reserved bit 6 set).
    bytes = Bytes[0x82, 0x09, 0x00, 0x01, 0x00,
      0x00, 0x03, 'a'.ord, '/'.ord, 'b'.ord, 0x40]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end

  it "rejects retain handling 3 (§3.8.3.1)" do
    # filter "a/b", options 0x30 (retain handling = 3, a reserved value).
    bytes = Bytes[0x82, 0x09, 0x00, 0x01, 0x00,
      0x00, 0x03, 'a'.ord, '/'.ord, 'b'.ord, 0x30]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end

  it "rejects reserved v3.1.1 subscription-option bits 2-7 [MQTT-3.8.3-4 v3.1.1]" do
    # v3 has no properties section; only the two QoS bits are defined. Options
    # 0x04 sets bit 2 (No Local, a v5-only flag) which is reserved in v3.1.1.
    bytes = Bytes[0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 'a'.ord, 0x04]
    mio = IO::Memory.new(bytes.size)
    mio.write bytes
    mio.rewind
    io = MQTT::Protocol::IO::V3.new(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode) { MQTT::Protocol::Packet.from_io(io) }
  end

  it "rejects a subscription identifier of 0 (§3.8.2.1.2)" do
    # props: subscription identifier (0x0B) = 0, then filter "a/b" options 0.
    bytes = Bytes[0x82, 0x0B, 0x00, 0x01, 0x02, 0x0B, 0x00,
      0x00, 0x03, 'a'.ord, '/'.ord, 'b'.ord, 0x00]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end

  # Decode against fixed bytes, asserting every field across two filters with
  # different option bits. Round-trips can pass when encode and decode share the
  # same wrong assumption; this pins the actual wire format.
  it "is parsed" do
    # 0x82 | rem_len 24 | packet id 10
    # props(9): subscription_identifier 0x0B=5, user property 0x26 "a"="b"
    # filter "a/b" options 0x01 (qos1)
    # filter "c/#" options 0x1E (qos2 | NL | RAP | RH=1)
    bytes = Bytes[
      0x82, 0x18,
      0x00, 0x0A,
      0x09, 0x0B, 0x05, 0x26, 0x00, 0x01, 0x61, 0x00, 0x01, 0x62,
      0x00, 0x03, 0x61, 0x2F, 0x62, 0x01,
      0x00, 0x03, 0x63, 0x2F, 0x23, 0x1E,
    ]
    subscribe = decode_v5(bytes).as(MQTT::Protocol::Subscribe)
    subscribe.packet_id.should eq 10u16
    subscribe.properties.subscription_identifier.should eq 5u32
    subscribe.properties.user_properties.should eq [{"a", "b"}]

    subscribe.topic_filters.size.should eq 2
    f1 = subscribe.topic_filters[0]
    f1.topic.should eq "a/b"
    f1.qos.should eq 1u8
    f1.no_local?.should be_false
    f1.retain_as_published?.should be_false
    f1.retain_handling.should eq 0u8

    f2 = subscribe.topic_filters[1]
    f2.topic.should eq "c/#"
    f2.qos.should eq 2u8
    f2.no_local?.should be_true
    f2.retain_as_published?.should be_true
    f2.retain_handling.should eq 1u8
  end
end

describe MQTT::Protocol::SubAck do
  it "encodes a v5 SUBACK with empty properties and one granted QoS" do
    suback = MQTT::Protocol::SubAck.new(
      reason_codes: [MQTT::Protocol::SubAck::ReasonCode::GrantedQoS1],
      packet_id: 1u16,
    )
    # 0x90, rem_len 4, packet id(00 01), props(00), reason(01)
    encode_v5(suback).should eq Bytes[0x90, 0x04, 0x00, 0x01, 0x00, 0x01]
  end

  it "round-trips per-entry reason codes and properties" do
    suback = MQTT::Protocol::SubAck.new(
      reason_codes: [
        MQTT::Protocol::SubAck::ReasonCode::GrantedQoS2,
        MQTT::Protocol::SubAck::ReasonCode::NotAuthorized,
      ],
      packet_id: 9u16,
      properties: MQTT::Protocol::SubAckProperties.new(reason_string: "partial"),
    )
    decoded = decode_v5(encode_v5(suback)).as(MQTT::Protocol::SubAck)
    decoded.reason_codes.should eq [
      MQTT::Protocol::SubAck::ReasonCode::GrantedQoS2,
      MQTT::Protocol::SubAck::ReasonCode::NotAuthorized,
    ]
    decoded.properties.reason_string.should eq "partial"
  end

  it "reports a bytesize matching the v5 serialization" do
    suback = MQTT::Protocol::SubAck.new(
      reason_codes: [MQTT::Protocol::SubAck::ReasonCode::GrantedQoS1],
      packet_id: 1u16,
      properties: MQTT::Protocol::SubAckProperties.new(reason_string: "x"),
    )
    suback.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(suback).size
  end

  it "raises PacketDecode when the properties length overruns remaining bytes" do
    bytes = Bytes[0x90, 0x04, 0x00, 0x01, 0x7F]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end
end

describe MQTT::Protocol::Unsubscribe do
  it "encodes a v5 UNSUBSCRIBE with empty properties" do
    unsubscribe = MQTT::Protocol::Unsubscribe.new(
      topics: ["a/b"],
      packet_id: 1u16,
    )
    # 0xA2, rem_len 8, packet id(00 01), props(00), topic(00 03 a / b)
    encode_v5(unsubscribe).should eq Bytes[
      0xA2, 0x08,
      0x00, 0x01,
      0x00,
      0x00, 0x03, 'a'.ord, '/'.ord, 'b'.ord,
    ]
  end

  it "round-trips UNSUBSCRIBE properties" do
    unsubscribe = MQTT::Protocol::Unsubscribe.new(
      topics: ["a/b", "c/d"],
      packet_id: 3u16,
      properties: MQTT::Protocol::UnsubscribeProperties.new(user_properties: [{"a", "b"}]),
    )
    decoded = decode_v5(encode_v5(unsubscribe)).as(MQTT::Protocol::Unsubscribe)
    decoded.topics.should eq ["a/b", "c/d"]
    decoded.properties.user_properties.should eq [{"a", "b"}]
  end

  it "reports a bytesize matching the v5 serialization" do
    unsubscribe = MQTT::Protocol::Unsubscribe.new(
      topics: ["a/b"], packet_id: 1u16,
      properties: MQTT::Protocol::UnsubscribeProperties.new(user_properties: [{"a", "b"}]),
    )
    unsubscribe.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(unsubscribe).size
  end

  it "raises PacketDecode when the properties length overruns remaining bytes" do
    bytes = Bytes[0xA2, 0x04, 0x00, 0x01, 0x7F]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end
end

describe MQTT::Protocol::UnsubAck do
  it "encodes a v5 UNSUBACK with a reason-code payload" do
    unsuback = MQTT::Protocol::UnsubAck.new(
      reason_codes: [MQTT::Protocol::UnsubAck::ReasonCode::Success],
      packet_id: 1u16,
    )
    # 0xB0, rem_len 4, packet id(00 01), props(00), reason(00)
    encode_v5(unsuback).should eq Bytes[0xB0, 0x04, 0x00, 0x01, 0x00, 0x00]
  end

  it "round-trips reason codes and properties" do
    unsuback = MQTT::Protocol::UnsubAck.new(
      reason_codes: [
        MQTT::Protocol::UnsubAck::ReasonCode::Success,
        MQTT::Protocol::UnsubAck::ReasonCode::NoSubscriptionExisted,
      ],
      packet_id: 4u16,
      properties: MQTT::Protocol::UnsubAckProperties.new(reason_string: "ok"),
    )
    decoded = decode_v5(encode_v5(unsuback)).as(MQTT::Protocol::UnsubAck)
    decoded.reason_codes.should eq [
      MQTT::Protocol::UnsubAck::ReasonCode::Success,
      MQTT::Protocol::UnsubAck::ReasonCode::NoSubscriptionExisted,
    ]
    decoded.properties.reason_string.should eq "ok"
  end

  it "encodes a v3 UNSUBACK as a bare packet id (no reason codes)" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::UnsubAck.new(packet_id: 1u16).to_io(io)
    mio.to_slice.should eq Bytes[0xB0, 0x02, 0x00, 0x01]
  end

  it "reports a bytesize matching the v5 serialization" do
    unsuback = MQTT::Protocol::UnsubAck.new(
      packet_id: 1u16,
      reason_codes: [MQTT::Protocol::UnsubAck::ReasonCode::Success],
      properties: MQTT::Protocol::UnsubAckProperties.new(reason_string: "ok"),
    )
    unsuback.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(unsuback).size
  end

  it "raises PacketDecode when remaining_length is below the v5 minimum" do
    # rem_len 1 has no room for even the packet id; the v5 branch lacks the
    # lower-bound guard the v3 branch has.
    bytes = Bytes[0xB0, 0x01, 0x00]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end
end

# 1.10: the SUBSCRIBE payload MUST contain at least one Topic Filter and
# Subscription Options pair [MQTT-3.8.3-2]; same for UNSUBSCRIBE topic
# filters [MQTT-3.10.3-2]. On v5 an empty properties section makes
# remaining_length 3 pass the old `> 2` check with zero filters.
describe "v5 empty subscription payloads" do
  it "rejects a v5 SUBSCRIBE with no topic filters" do
    # rem_len 3: packet id (00 01) + empty props (00), no filters.
    bytes = Bytes[0x82, 0x03, 0x00, 0x01, 0x00]
    mio = IO::Memory.new(bytes.size)
    mio.write bytes
    mio.rewind
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) do
      MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO::V5.new(mio))
    end
    ex.reason_code.should eq 0x82u8
  end

  it "rejects a v5 UNSUBSCRIBE with no topic filters" do
    # rem_len 3: packet id (00 01) + empty props (00), no topics.
    bytes = Bytes[0xA2, 0x03, 0x00, 0x01, 0x00]
    mio = IO::Memory.new(bytes.size)
    mio.write bytes
    mio.rewind
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) do
      MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO::V5.new(mio))
    end
    ex.reason_code.should eq 0x82u8
  end
end
