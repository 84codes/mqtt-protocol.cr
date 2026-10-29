require "./spec_helper"

# 1.7: a PUBLISH Topic Name MUST be a well-formed UTF-8 string without U+0000
# ([MQTT-3.3.2-1] via [MQTT-1.5.4-1/2]). The topic stays raw Bytes on the hot
# path, so validation is a single allocation-free byte scan fused with the
# existing wildcard check.
private def decode_publish_topic(topic : Bytes)
  mio = IO::Memory.new
  io = MQTT::Protocol::IO.v3(mio)
  io.write_byte 0x30u8 # PUBLISH, QoS 0
  io.write_remaining_length(2 + topic.size + 1)
  io.write_bytes topic
  io.write_byte 0x78u8 # 1-byte payload
  mio.rewind
  MQTT::Protocol::Packet.from_io(MQTT::Protocol::IO.v3(mio))
end

private def expect_rejected(topic : Bytes)
  expect_raises(MQTT::Protocol::Error::PacketDecode) { decode_publish_topic(topic) }
end

describe "PUBLISH topic validation" do
  it "rejects an embedded U+0000" do
    expect_rejected Bytes[0x61, 0x00, 0x62] # "a\0b"
  end

  it "rejects invalid UTF-8 lead bytes" do
    expect_rejected Bytes[0xFF, 0xFE]
  end

  it "rejects a bare continuation byte" do
    expect_rejected Bytes[0x61, 0x80]
  end

  it "rejects overlong encodings" do
    expect_rejected Bytes[0xC0, 0x80] # overlong U+0000
    expect_rejected Bytes[0xE0, 0x80, 0x80]
  end

  it "rejects a truncated multibyte sequence" do
    expect_rejected Bytes[0x61, 0xC3]       # 2-byte lead, nothing after
    expect_rejected Bytes[0xE2, 0x82]       # 3-byte lead, one continuation
    expect_rejected Bytes[0xF0, 0x9F, 0x99] # 4-byte lead, two continuations
  end

  it "rejects UTF-16 surrogates" do
    expect_rejected Bytes[0xED, 0xA0, 0x80] # U+D800
  end

  it "rejects codepoints above U+10FFFF" do
    expect_rejected Bytes[0xF4, 0x90, 0x80, 0x80]
    expect_rejected Bytes[0xF5, 0x80, 0x80, 0x80]
  end

  it "accepts valid multibyte topics" do
    topic = "sensor/温度/☃".to_slice
    packet = decode_publish_topic(topic).as(MQTT::Protocol::Publish)
    packet.topic.should eq "sensor/温度/☃"
  end

  it "rejects NUL and ill-formed UTF-8 at construction too" do
    expect_raises(ArgumentError) do
      MQTT::Protocol::Publish.new("a\u0000b", "x".to_slice)
    end
    expect_raises(ArgumentError) do
      MQTT::Protocol::Publish.new(Bytes[0xFF], "x".to_slice)
    end
  end
end
