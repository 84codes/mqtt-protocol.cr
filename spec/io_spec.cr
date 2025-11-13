require "./spec_helper"

describe MQTT::Protocol::IO do
  it "can read packet" do
    mio = IO::Memory.new
    # Write a raw PingReq
    mio.write_byte(12u8 << 4)
    mio.write_byte(0u8)
    mio.rewind

    packet = MQTT::Protocol::IO.new(mio).read_packet

    packet.should be_a MQTT::Protocol::PingReq
  end

  it "can write packet" do
    mio = IO::Memory.new

    pingreq = MQTT::Protocol::PingReq.new
    MQTT::Protocol::IO.new(mio).write_packet(pingreq)
    mio.rewind

    mio.to_slice.should eq Bytes[12u8 << 4, 0u8]
  end

  it "can write int" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.new(mio)

    io.write_int 500

    mio.rewind
    res = UInt16.from_io(mio, ::IO::ByteFormat::NetworkEndian)

    res.should eq 500
  end

  it "can write byte" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.new(mio)

    io.write_byte 33u8

    mio.rewind
    res = UInt8.from_io(mio, ::IO::ByteFormat::NetworkEndian)

    res.should eq 33u8
  end

  it "can write string" do
    str = "hello world"

    mio = IO::Memory.new
    io = MQTT::Protocol::IO.new(mio)

    io.write_string str

    mio.rewind
    len = UInt16.from_io(mio, ::IO::ByteFormat::NetworkEndian)
    res = mio.read_string(len)

    res.should eq str
  end

  it "can write bytes" do
    bytes = Bytes[1u8, 2u8, 3u8]

    mio = IO::Memory.new
    io = MQTT::Protocol::IO.new(mio)

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
    io = MQTT::Protocol::IO.new(mio)

    io.write_bytes_raw bytes
    mio.rewind

    res = Bytes.new(3)
    mio.read_fully res

    res.should eq bytes
  end

  it "can write remaining length 1 byte" do
    mio = IO::Memory.new
    io = MQTT::Protocol::IO.new(mio)
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
    io = MQTT::Protocol::IO.new(mio)
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
    io = MQTT::Protocol::IO.new(mio)
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
    io = MQTT::Protocol::IO.new(mio)
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

    io = MQTT::Protocol::IO.new(mio)
    data = io.read_int

    data.should eq 100u16
  end

  it "can read byte" do
    mio = IO::Memory.new
    mio.write_byte 100u8
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
    data = io.read_byte

    data.should eq 100u8
  end

  it "can read string" do
    str = "hello world"

    mio = IO::Memory.new
    str.bytesize.to_u16.to_io(mio, ::IO::ByteFormat::NetworkEndian)
    mio.write str.to_slice
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
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
    io = MQTT::Protocol::IO.new(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode) do
      io.read_string
    end
  end

  it "can read remaining length 1 byte" do
    mio = IO::Memory.new
    mio.write_byte 0x00
    mio.write_byte 0x7F
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)

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

    io = MQTT::Protocol::IO.new(mio)

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

    io = MQTT::Protocol::IO.new(mio)

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

    io = MQTT::Protocol::IO.new(mio, max_packet_size: 268435455u32)

    len1 = io.read_remaining_length
    len2 = io.read_remaining_length

    len1.should eq expected1
    len2.should eq expected2
  end

  it "wont read remaning length 5 bytes" do
    mio = IO::Memory.new
    mio.write Bytes[0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x01u8]
    mio.rewind

    io = MQTT::Protocol::IO.new(mio)
    expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid remaining length/) do
      io.read_remaining_length
    end
  end
end
