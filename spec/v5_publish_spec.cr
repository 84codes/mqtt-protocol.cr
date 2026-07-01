require "./spec_helper"

# PUBLISH and the QoS-ack packets at v5 (MQTT5_FINDINGS.md section 4).
#
# PUBLISH gains a properties section (after the packet id, before the payload)
# and may carry an empty topic when io.version >= V5 (a Topic Alias property
# substitutes - resolution is the consumer's job, 3.7).
#
# PUBACK/PUBREC/PUBREL/PUBCOMP gain a reason-code byte and properties, both
# omittable: reason 0x00 + no properties => remaining length 2 (packet id
# only); reason set but no properties => remaining length 3.

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

private def encode_v3(packet)
  mio = IO::Memory.new
  io = MQTT::Protocol::IO::V3.new(mio)
  packet.to_io(io)
  mio.to_slice
end

private def decode_v3(bytes : Bytes)
  mio = IO::Memory.new(bytes.size)
  mio.write bytes
  mio.rewind
  io = MQTT::Protocol::IO::V3.new(mio)
  MQTT::Protocol::Packet.from_io(io)
end

describe MQTT::Protocol::Publish do
  it "encodes a v5 QoS0 PUBLISH with an empty properties section" do
    publish = MQTT::Protocol::Publish.new(
      topic: "a/b",
      payload: "hi".to_slice,
      packet_id: nil,
      dup: false,
      qos: 0u8,
      retain: false,
    )
    # 0x30, rem_len 8, topic(00 03 a / b), props(00), payload(h i)
    encode_v5(publish).should eq Bytes[
      0x30, 0x08,
      0x00, 0x03, 'a'.ord, '/'.ord, 'b'.ord,
      0x00,
      'h'.ord, 'i'.ord,
    ]
  end

  it "round-trips PUBLISH properties" do
    props = MQTT::Protocol::PublishProperties.new(
      payload_format_indicator: true,
      message_expiry_interval: 120u32,
      response_topic: "responses/1",
      correlation_data: Bytes[1, 2, 3],
      user_properties: [{"a", "b"}],
      subscription_identifiers: [10u32, 20u32],
      content_type: "application/json",
    )
    publish = MQTT::Protocol::Publish.new(
      topic: "t",
      payload: "payload".to_slice,
      packet_id: 5u16,
      dup: false,
      qos: 1u8,
      retain: false,
      properties: props,
    )
    decoded = decode_v5(encode_v5(publish)).as(MQTT::Protocol::Publish)
    decoded.properties.should eq props
    decoded.packet_id.should eq 5u16
    String.new(decoded.payload).should eq "payload"
  end

  it "allows an empty topic with a Topic Alias when io.version >= V5" do
    bytes = Bytes[
      0x30, 0x08,
      0x00, 0x00,             # empty topic
      0x03, 0x23, 0x00, 0x01, # props: Topic Alias = 1
      'h'.ord, 'i'.ord,       # payload
    ]
    publish = decode_v5(bytes).as(MQTT::Protocol::Publish)
    publish.topic.should eq ""
    publish.properties.topic_alias.should eq 1u16
  end

  it "exposes the topic both as a decoded String and as raw bytes" do
    bytes = Bytes[
      0x30, 0x09,
      0x00, 0x05, 't'.ord, 'o'.ord, 'p'.ord, 'i'.ord, 'c'.ord, # topic "topic"
      0x00,                                                    # empty properties
      'h'.ord,                                                 # payload
    ]
    publish = decode_v5(bytes).as(MQTT::Protocol::Publish)
    publish.topic.should eq "topic"
    publish.topic_bytes.should eq "topic".to_slice
  end

  it "still rejects an empty topic on a v3 connection" do
    bytes = Bytes[
      0x30, 0x04,
      0x00, 0x00, # empty topic
      'h'.ord, 'i'.ord,
    ]
    mio = IO::Memory.new(bytes.size)
    mio.write bytes
    mio.rewind
    io = MQTT::Protocol::IO::V3.new(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode) do
      MQTT::Protocol::Packet.from_io(io)
    end
  end

  it "reports a bytesize matching the v5 serialization" do
    publish = MQTT::Protocol::Publish.new(
      topic: "t", payload: "payload".to_slice, packet_id: 5u16,
      dup: false, qos: 1u8, retain: false,
      properties: MQTT::Protocol::PublishProperties.new(message_expiry_interval: 120u32),
    )
    publish.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(publish).size
  end

  it "reports a bytesize matching the v3 serialization" do
    publish = MQTT::Protocol::Publish.new(
      topic: "t", payload: "payload".to_slice, packet_id: 5u16,
      dup: false, qos: 1u8, retain: false,
    )
    publish.bytesize(MQTT::Protocol::Version::V3_1_1).to_i.should eq encode_v3(publish).size
  end

  it "omits the properties section when written to a v3 io" do
    publish = MQTT::Protocol::Publish.new(
      topic: "a/b", payload: "hi".to_slice, packet_id: nil,
      dup: false, qos: 0u8, retain: false,
      properties: MQTT::Protocol::PublishProperties.new(message_expiry_interval: 120u32),
    )
    # No 0x00 properties prefix, no property bytes: 0x30, rem 7, topic, payload.
    encode_v3(publish).should eq Bytes[
      0x30, 0x07, 0x00, 0x03, 'a'.ord, '/'.ord, 'b'.ord, 'h'.ord, 'i'.ord,
    ]
  end

  it "raises PacketDecode when the topic length exceeds remaining_length" do
    # rem_len 2, but the topic declares 5 bytes -> remaining_length -= 7 underflows.
    bytes = Bytes[0x30, 0x02, 0x00, 0x05, 'a'.ord, 'b'.ord, 'c'.ord, 'd'.ord, 'e'.ord]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end

  it "raises PacketDecode when the properties length overruns remaining bytes" do
    # rem_len 4: topic "a" (3 bytes) leaves 1 byte; property length VBI claims 127.
    bytes = Bytes[0x30, 0x04, 0x00, 0x01, 'a'.ord, 0x7F]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end

  it "raises PacketDecode when truncated mid-payload" do
    # rem_len claims 10 but only the topic and empty properties are present.
    bytes = Bytes[0x30, 0x0A, 0x00, 0x01, 'a'.ord, 0x00]
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end

  it "rejects a Subscription Identifier of 0 [MQTT-3.8.2-1]" do
    # QoS0 PUBLISH, topic "a", property Subscription Identifier (0x0B) = 0.
    # Valid range is 1..268,435,455, so 0 is a Protocol Error.
    bytes = Bytes[0x30, 0x06, 0x00, 0x01, 'a'.ord, 0x02, 0x0B, 0x00]
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { decode_v5(bytes) }
    ex.reason_code.should eq 0x82u8
  end

  # Decode against fixed bytes, asserting every field including the fixed-header
  # flag bits. Round-trips can pass when encode and decode share the same wrong
  # assumption; this pins the actual wire format.
  it "is parsed" do
    # 0x33 = type 3 | dup 0 | qos 1 | retain 1
    # rem_len 40 | topic "sensor/temp" | packet id 42
    # props(20): payload_format 0x01=1, message_expiry 0x02=120, content_type 0x03="text/plain"
    # payload "21.5"
    bytes = Bytes[
      0x33, 0x28,
      0x00, 0x0B, 0x73, 0x65, 0x6E, 0x73, 0x6F, 0x72, 0x2F, 0x74, 0x65, 0x6D, 0x70,
      0x00, 0x2A,
      0x14, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x78,
      0x03, 0x00, 0x0A, 0x74, 0x65, 0x78, 0x74, 0x2F, 0x70, 0x6C, 0x61, 0x69, 0x6E,
      0x32, 0x31, 0x2E, 0x35,
    ]
    publish = decode_v5(bytes).as(MQTT::Protocol::Publish)
    publish.topic.should eq "sensor/temp"
    publish.packet_id.should eq 42u16
    publish.qos.should eq 1u8
    publish.retain?.should be_true
    publish.dup?.should be_false
    String.new(publish.payload).should eq "21.5"
    publish.properties.payload_format_indicator.should be_true
    publish.properties.message_expiry_interval.should eq 120u32
    publish.properties.content_type.should eq "text/plain"
  end
end

describe MQTT::Protocol::PubAck do
  it "omits reason code and properties when reason is Success (remaining length 2)" do
    puback = MQTT::Protocol::PubAck.new(packet_id: 10u16)
    encode_v5(puback).should eq Bytes[0x40, 0x02, 0x00, 0x0A]
  end

  it "writes the reason code but omits properties when reason is set (remaining length 3)" do
    puback = MQTT::Protocol::PubAck.new(
      packet_id: 10u16,
      reason_code: MQTT::Protocol::PubAck::ReasonCode::NotAuthorized,
    )
    encode_v5(puback).should eq Bytes[0x40, 0x03, 0x00, 0x0A, 0x87]
  end

  it "writes reason code and properties when properties are present" do
    puback = MQTT::Protocol::PubAck.new(
      packet_id: 10u16,
      reason_code: MQTT::Protocol::PubAck::ReasonCode::Success,
      properties: MQTT::Protocol::PubAckProperties.new(reason_string: "x"),
    )
    # rem_len 8: packet id(2) + reason(1) + props(05: len 04, 1F 00 01 'x')
    encode_v5(puback).should eq Bytes[
      0x40, 0x08, 0x00, 0x0A, 0x00,
      0x04, 0x1F, 0x00, 0x01, 'x'.ord,
    ]
  end

  it "decodes a bare packet id (remaining length 2) as Success" do
    puback = decode_v5(Bytes[0x40, 0x02, 0x00, 0x0A]).as(MQTT::Protocol::PubAck)
    puback.packet_id.should eq 10u16
    puback.reason_code.should eq MQTT::Protocol::PubAck::ReasonCode::Success
  end

  it "round-trips reason code and properties" do
    puback = MQTT::Protocol::PubAck.new(
      packet_id: 99u16,
      reason_code: MQTT::Protocol::PubAck::ReasonCode::QuotaExceeded,
      properties: MQTT::Protocol::PubAckProperties.new(
        reason_string: "over quota",
        user_properties: [{"a", "b"}],
      ),
    )
    decoded = decode_v5(encode_v5(puback)).as(MQTT::Protocol::PubAck)
    decoded.reason_code.should eq MQTT::Protocol::PubAck::ReasonCode::QuotaExceeded
    decoded.properties.reason_string.should eq "over quota"
  end

  it "encodes a v3 PUBACK as a bare packet id" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO::V3.new(mio)
    MQTT::Protocol::PubAck.new(packet_id: 10u16).to_io(io)
    mio.to_slice.should eq Bytes[0x40, 0x02, 0x00, 0x0A]
  end

  it "reports a bytesize matching the v5 serialization" do
    puback = MQTT::Protocol::PubAck.new(
      packet_id: 10u16, reason_code: MQTT::Protocol::PubAck::ReasonCode::NotAuthorized)
    puback.bytesize(MQTT::Protocol::Version::V5).to_i.should eq encode_v5(puback).size
  end

  it "reports a bytesize matching the v3 serialization (bare packet id)" do
    puback = MQTT::Protocol::PubAck.new(
      packet_id: 10u16, reason_code: MQTT::Protocol::PubAck::ReasonCode::NotAuthorized)
    puback.bytesize(MQTT::Protocol::Version::V3_1_1).to_i.should eq encode_v3(puback).size
  end

  it "rejects an invalid reason-code byte" do
    bytes = Bytes[0x40, 0x03, 0x00, 0x0A, 0x7E] # 0x7E is not a PUBACK reason code
    expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_v5(bytes) }
  end
end

describe MQTT::Protocol::PubRec do
  it "round-trips reason code and properties" do
    pubrec = MQTT::Protocol::PubRec.new(
      packet_id: 7u16,
      reason_code: MQTT::Protocol::PubRec::ReasonCode::NoMatchingSubscribers,
    )
    decoded = decode_v5(encode_v5(pubrec)).as(MQTT::Protocol::PubRec)
    decoded.packet_id.should eq 7u16
    decoded.reason_code.should eq MQTT::Protocol::PubRec::ReasonCode::NoMatchingSubscribers
  end
end

describe MQTT::Protocol::PubRel do
  it "keeps fixed-header flags 0b0010 and carries a reason code" do
    pubrel = MQTT::Protocol::PubRel.new(
      packet_id: 7u16,
      reason_code: MQTT::Protocol::PubRel::ReasonCode::PacketIdentifierNotFound,
    )
    bytes = encode_v5(pubrel)
    bytes[0].should eq 0x62 # (6 << 4) | 0b0010
    decoded = decode_v5(bytes).as(MQTT::Protocol::PubRel)
    decoded.reason_code.should eq MQTT::Protocol::PubRel::ReasonCode::PacketIdentifierNotFound
  end

  it "decodes a bare v3 PUBREL (remaining length 2)" do
    pubrel = decode_v3(Bytes[0x62, 0x02, 0x00, 0x05]).as(MQTT::Protocol::PubRel)
    pubrel.packet_id.should eq 5u16
    pubrel.reason_code.should eq MQTT::Protocol::PubRel::ReasonCode::Success
  end

  it "rejects a v3 PUBREL carrying a reason byte (remaining length must be 2)" do
    expect_raises(MQTT::Protocol::Error::PacketDecode) do
      decode_v3(Bytes[0x62, 0x03, 0x00, 0x05, 0x92])
    end
  end
end

describe MQTT::Protocol::PubComp do
  it "uses fixed-header flags 0b0000 (0x70)" do
    # Pins the pre-existing v3 wire-bug fix (flags were 0b0010 -> corrected to
    # 0b0000); round-trips alone would not catch a flag-bit regression.
    pubcomp = MQTT::Protocol::PubComp.new(packet_id: 7u16)
    encode_v5(pubcomp).should eq Bytes[0x70, 0x02, 0x00, 0x07]
  end

  it "round-trips reason code" do
    pubcomp = MQTT::Protocol::PubComp.new(
      packet_id: 7u16,
      reason_code: MQTT::Protocol::PubComp::ReasonCode::PacketIdentifierNotFound,
    )
    decoded = decode_v5(encode_v5(pubcomp)).as(MQTT::Protocol::PubComp)
    decoded.reason_code.should eq MQTT::Protocol::PubComp::ReasonCode::PacketIdentifierNotFound
  end

  it "rejects a v3 PUBCOMP carrying a reason byte (remaining length must be 2)" do
    expect_raises(MQTT::Protocol::Error::PacketDecode) do
      decode_v3(Bytes[0x70, 0x03, 0x00, 0x05, 0x92])
    end
  end
end
