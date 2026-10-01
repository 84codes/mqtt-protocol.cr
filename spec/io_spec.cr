require "./spec_helper"

describe MQTT::Protocol::IO do
  it "can read packet" do
    mio = IO::Memory.new
    # Write a raw PingReq
    mio.write_byte(12u8 << 4)
    mio.write_byte(0u8)
    mio.rewind

    packet = MQTT::Protocol::IO.v3(mio).read_packet

    packet.should be_a MQTT::Protocol::PingReq
  end

  it "can write packet" do
    mio = IO::Memory.new

    pingreq = MQTT::Protocol::PingReq.new
    MQTT::Protocol::IO.v3(mio).write_packet(pingreq)
    mio.rewind

    mio.to_slice.should eq Bytes[12u8 << 4, 0u8]
  end

  it "can write int" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)

    io.write_int 500

    mio.rewind
    res = UInt16.from_io(mio, ::IO::ByteFormat::NetworkEndian)

    res.should eq 500
  end

  it "can write byte" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)

    io.write_byte 33u8

    mio.rewind
    res = UInt8.from_io(mio, ::IO::ByteFormat::NetworkEndian)

    res.should eq 33u8
  end

  it "can write string" do
    str = "hello world"

    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)

    io.write_string str

    mio.rewind
    len = UInt16.from_io(mio, ::IO::ByteFormat::NetworkEndian)
    res = mio.read_string(len)

    res.should eq str
  end

  it "can write bytes" do
    bytes = Bytes[1u8, 2u8, 3u8]

    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)

    io.write_bytes bytes

    mio.rewind
    len = UInt16.from_io(mio, ::IO::ByteFormat::NetworkEndian)
    res = Bytes.new(len)
    mio.read_fully res

    res.should eq bytes
  end

  it "can write bytes raw" do
    bytes = "abc".to_slice

    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)

    io.write_bytes_raw bytes
    mio.rewind

    res = Bytes.new(3)
    mio.read_fully res

    res.should eq bytes
  end

  it "can write remaining length 1 byte" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    io.write_remaining_length(0x00)
    io.write_remaining_length(0x7F)
    mio.rewind

    len1 = mio.read_byte
    len2 = mio.read_byte

    len1.should eq 0x00
    len2.should eq 0x7F

    # nothing should be left
    mio.peek.empty?
  end

  it "can write remaining length 2 bytes" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    io.write_remaining_length(128)
    io.write_remaining_length(16_383)
    mio.rewind

    len1 = Bytes.new(2)
    len2 = Bytes.new(2)

    mio.read(len1)
    mio.read(len2)

    len1.should eq Bytes[0x80, 0x01]
    len2.should eq Bytes[0xFF, 0x7F]

    # nothing should be left
    mio.peek.empty?
  end

  it "can write remaining length 3 bytes" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    io.write_remaining_length(16_384)
    io.write_remaining_length(2_097_151)
    mio.rewind

    len1 = Bytes.new(3)
    len2 = Bytes.new(3)

    mio.read(len1)
    mio.read(len2)

    len1.should eq Bytes[0x80, 0x80, 0x01]
    len2.should eq Bytes[0xFF, 0xFF, 0x7F]

    # nothing should be left
    mio.peek.empty?
  end

  it "can write remaining length 4 bytes" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    io.write_remaining_length(2_097_152)
    io.write_remaining_length(268_435_455)
    mio.rewind

    len1 = Bytes.new(4)
    len2 = Bytes.new(4)

    mio.read(len1)
    mio.read(len2)

    len1.should eq Bytes[0x80, 0x80, 0x80, 0x01]
    len2.should eq Bytes[0xFF, 0xFF, 0xFF, 0x7F]

    # nothing should be left
    mio.peek.empty?
  end

  it "can read int" do
    mio = IO::Memory.new
    100u16.to_io(mio, ::IO::ByteFormat::NetworkEndian)
    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)
    data = io.read_int

    data.should eq 100u16
  end

  it "can read byte" do
    mio = IO::Memory.new
    mio.write_byte 100u8
    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)
    data = io.read_byte

    data.should eq 100u8
  end

  it "can read string" do
    str = "hello world"

    mio = IO::Memory.new
    str.bytesize.to_u16.to_io(mio, ::IO::ByteFormat::NetworkEndian)
    mio.write str.to_slice
    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)
    data = io.read_string

    data.should eq "hello world"
  end

  it "does not read a string containing null character" do
    mio = IO::Memory.new
    str1 = "hello"
    str2 = "world"
    (2 + str1.bytesize + str2.bytesize).to_u16.to_io(mio, ::IO::ByteFormat::NetworkEndian)
    mio.write str1.to_slice
    0x0000u16.to_io(mio, ::IO::ByteFormat::NetworkEndian)
    mio.write str2.to_slice
    mio.rewind
    io = MQTT::Protocol::IO.v3(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode) do
      io.read_string
    end
  end

  it "can read remaining length 1 byte" do
    mio = IO::Memory.new
    mio.write_byte 0x00
    mio.write_byte 0x7F
    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)

    len1 = io.read_remaining_length
    len2 = io.read_remaining_length

    len1.should eq 0x00
    len2.should eq 0x7F
  end

  it "can read remaining length 2 byte" do
    mio = IO::Memory.new
    mio.write Bytes[0x80u8, 0x01u8]
    mio.write Bytes[0xFFu8, 0x7Fu8]

    expected1 = (0x80 & 127) + (0x01 * 128)
    expected2 = (0xFF & 127) + (0x7F * 128)

    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)

    len1 = io.read_remaining_length
    len2 = io.read_remaining_length

    len1.should eq expected1
    len2.should eq expected2
  end

  it "can read remaining length 3 byte" do
    mio = IO::Memory.new
    mio.write Bytes[0x80u8, 0x80u8, 0x01u8]
    mio.write Bytes[0xFFu8, 0xFFu8, 0x7Fu8]

    expected1 = (0x80 & 127) + (0x80 & 127) * 128 + (0x01 * 128 * 128)
    expected2 = (0xFF & 127) + (0xFF & 127) * 128 + (0x7F * 128 * 128)

    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)

    len1 = io.read_remaining_length
    len2 = io.read_remaining_length

    len1.should eq expected1
    len2.should eq expected2
  end

  it "can read remaining length 4 byte" do
    mio = IO::Memory.new
    mio.write Bytes[0x80u8, 0x80u8, 0x80u8, 0x01u8]
    mio.write Bytes[0xFFu8, 0xFFu8, 0xFFu8, 0x7Fu8]

    expected1 = (0x80 & 127) + ((0x80 & 127) * 128) + ((0x80 & 127) * 128 * 128) + (0x01 * 128 * 128 * 128)
    expected2 = (0xFF & 127) + ((0xFF & 127) * 128) + ((0xFF & 127) * 128 * 128) + (0x7F * 128 * 128 * 128)

    mio.rewind

    io = MQTT::Protocol::IO.v3(mio, max_packet_size: 268435455u32)

    len1 = io.read_remaining_length
    len2 = io.read_remaining_length

    len1.should eq expected1
    len2.should eq expected2
  end

  it "wont read remaning length 5 bytes" do
    mio = IO::Memory.new
    mio.write Bytes[0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x01u8]
    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid variable byte integer/) do
      io.read_remaining_length
    end
  end

  it "checks max_packet_size on remaining length" do
    mio = IO::Memory.new
    mio.write Bytes[0xFFu8, 0xFFu8, 0xFFu8, 0x7Fu8]

    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)

    io = MQTT::Protocol::IO.v3(mio, max_packet_size: 268435454u32)
    expect_raises(MQTT::Protocol::Error::PacketTooLarge) do
      io.read_remaining_length
    end
  end

  it "checks read_string for max_packet_size" do
    mio = IO::Memory.new
    str1 = "hello"
    str1.bytesize.to_u16.to_io(mio, ::IO::ByteFormat::NetworkEndian)
    mio.write str1.to_slice
    mio.rewind
    io = MQTT::Protocol::IO.v3(mio, max_packet_size: 4)
    expect_raises(MQTT::Protocol::Error::PacketTooLarge) do
      io.read_string
    end
  end
  it "checks read_bytes for max_packet_size" do
    mio = IO::Memory.new
    str1 = "hello"
    str1.bytesize.to_u16.to_io(mio, ::IO::ByteFormat::NetworkEndian)
    mio.write str1.to_slice
    mio.rewind
    io = MQTT::Protocol::IO.v3(mio, max_packet_size: 4)
    expect_raises(MQTT::Protocol::Error::PacketTooLarge) do
      io.read_bytes
    end
  end
end

# 2.6: the IO models the concrete negotiated version, so a v3.1 (MQIsdp)
# connection is not misreported as v3.1.1, and a version pinned at construction
# is distinguishable from one not yet read off the wire.
describe "IO version modeling" do
  it "reports the concrete v3 version" do
    io = MQTT::Protocol::IO.for(MQTT::Protocol::Version::V3_1, IO::Memory.new)
    io.version.should eq MQTT::Protocol::Version::V3_1
  end

  it "is negotiated when the version is pinned at construction" do
    MQTT::Protocol::IO.for(MQTT::Protocol::Version::V3_1, IO::Memory.new)
      .negotiated?.should be_true
    MQTT::Protocol::IO.v5(IO::Memory.new).negotiated?.should be_true
  end

  it "reports Unknown before CONNECT" do
    io = MQTT::Protocol::IO.new(IO::Memory.new)
    io.negotiated?.should be_false
    io.version.should eq MQTT::Protocol::Version::Unknown
  end

  it "sizes a rejection CONNACK as v3 before CONNECT" do
    io = MQTT::Protocol::IO.new(IO::Memory.new)
    connack = MQTT::Protocol::Connack.new(
      false, MQTT::Protocol::Connack::ReasonCode::UnsupportedProtocolVersion)
    io.bytesize(connack).should eq connack.bytesize(MQTT::Protocol::Version::V3_1_1)
  end

  it "is not negotiated when built for Unknown" do
    MQTT::Protocol::IO.for(MQTT::Protocol::Version::Unknown, IO::Memory.new)
      .negotiated?.should be_false
  end

  it "refuses Unknown as a pinned v3 version" do
    expect_raises(ArgumentError) do
      MQTT::Protocol::IO.v3(IO::Memory.new, version: MQTT::Protocol::Version::Unknown)
    end
  end

  it "read_connect leaves the IO reporting v3.1 for an MQIsdp client" do
    mio = IO::Memory.new
    w = MQTT::Protocol::IO.v3(mio)
    w.write_byte 0b00010000u8 # CONNECT
    # MQIsdp(2+6) + level(1) + flags(1) + keepalive(2) + client id(2+3) = 17
    w.write_remaining_length 17
    w.write_string "MQIsdp"
    w.write_byte 0x03u8       # protocol level 3 (MQTT 3.1)
    w.write_byte 0b00000010u8 # clean session
    w.write_int 30u16
    w.write_string "abc"
    mio.rewind
    io = MQTT::Protocol::IO.new(mio)
    connect = io.read_connect
    connect.version.should eq MQTT::Protocol::Version::V3_1
    io.version.should eq MQTT::Protocol::Version::V3_1
    io.negotiated?.should be_true
  end
end

# The bootstrap state exists to close a misparse hole: until CONNECT names the
# version there is no framing that can be trusted, so a packet of any other type
# is refused before a single body byte is read - rather than parsed with a
# guessed framing.
describe "IO bootstrap state" do
  it "refuses a non-CONNECT first packet before reading its body" do
    mio = IO::Memory.new
    # A v5 PUBLISH: v3 framing would silently parse it as topic + payload,
    # missing the properties section entirely.
    mio.write Bytes[0x30, 0x08, 0x00, 0x03, 0x61, 0x2F, 0x62, 0x00, 0x68, 0x69]
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode, /first packet must be CONNECT/) do
      io.read_packet
    end
    # Refused at the type byte: the body is still unread.
    mio.pos.should eq 1
  end

  it "reads normally once CONNECT has named the version" do
    mio = IO::Memory.new
    w = MQTT::Protocol::IO.v5(mio)
    w.write_byte 0b0001_0000u8
    w.write_remaining_length 13u8
    w.write_string "MQTT"
    w.write_byte 0x05u8
    w.write_byte 0b0000_0010u8
    w.write_int 60u16
    w.write_byte 0x00u8
    w.write_string ""
    # A v5 PUBLISH with an empty properties section, legal now the version is known.
    w.write_packet MQTT::Protocol::Publish.new("a/b", "hi".to_slice, nil, false, 0u8, false)
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
    io.read_connect.version.should eq MQTT::Protocol::Version::V5
    io.read_packet.as(MQTT::Protocol::Publish).topic.should eq "a/b"
  end
end

private def connect_for(version : MQTT::Protocol::Version) : MQTT::Protocol::Connect
  MQTT::Protocol::Connect.new("c", true, 10u16, nil, nil, nil, version)
end

# Once negotiated the version is fixed for the connection's life: a later
# CONNECT, read or written, must not reframe it ([MQTT-3.1.0-2]). One for the
# same version is let through; refusing it is up to the library user.
describe "IO version is write-once" do
  it "rejects a second CONNECT for another version without reframing" do
    mio = IO::Memory.new
    MQTT::Protocol::IO.new(mio).write_packet connect_for(MQTT::Protocol::Version::V5)
    MQTT::Protocol::IO.new(mio).write_packet connect_for(MQTT::Protocol::Version::V3_1_1)
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
    io.read_connect
    ex = expect_raises(MQTT::Protocol::Error::ProtocolError) { io.read_packet }
    ex.reason_code.should eq 0x82u8
    io.version.should eq MQTT::Protocol::Version::V5
  end

  it "reads a second CONNECT for the same version" do
    mio = IO::Memory.new
    MQTT::Protocol::IO.new(mio).write_packet connect_for(MQTT::Protocol::Version::V5)
    MQTT::Protocol::IO.new(mio).write_packet connect_for(MQTT::Protocol::Version::V5)
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
    io.read_connect
    io.read_packet.as(MQTT::Protocol::Connect).version.should eq MQTT::Protocol::Version::V5
  end

  it "rejects a CONNECT for another version on a pinned IO" do
    mio = IO::Memory.new
    MQTT::Protocol::IO.new(mio).write_packet connect_for(MQTT::Protocol::Version::V5)
    mio.rewind

    io = MQTT::Protocol::IO.v3(mio)
    expect_raises(MQTT::Protocol::Error::ProtocolError) { io.read_connect }
    io.version.should eq MQTT::Protocol::Version::V3_1_1
  end

  it "negotiates the version when writing a CONNECT on a bootstrap IO" do
    io = MQTT::Protocol::IO.new(IO::Memory.new)
    io.write_packet connect_for(MQTT::Protocol::Version::V5)
    io.version.should eq MQTT::Protocol::Version::V5
    io.negotiated?.should be_true
  end

  it "negotiates the version when Connect.from_io is called directly on a bootstrap IO" do
    mio = IO::Memory.new
    MQTT::Protocol::IO.new(mio).write_packet connect_for(MQTT::Protocol::Version::V5)
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
    io.read_byte? # fixed header type + flags
    remaining_length = io.read_remaining_length
    MQTT::Protocol::Connect.from_io(io, 0u8, remaining_length)
    io.version.should eq MQTT::Protocol::Version::V5
    io.negotiated?.should be_true
  end

  it "writes a second CONNECT for the same version" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.new(mio)
    io.write_packet connect_for(MQTT::Protocol::Version::V5)
    written = mio.size
    io.write_packet connect_for(MQTT::Protocol::Version::V5)
    mio.size.should eq written * 2
  end

  it "refuses to write a CONNECT for another version, before any byte" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.v3(mio)
    expect_raises(MQTT::Protocol::Error::PacketEncode) do
      io.write_packet connect_for(MQTT::Protocol::Version::V5)
    end
    mio.size.should eq 0
    io.version.should eq MQTT::Protocol::Version::V3_1_1
  end
end
