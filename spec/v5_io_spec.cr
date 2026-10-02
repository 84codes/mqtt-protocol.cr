require "./spec_helper"

# Wire primitives added for MQTT 5.0 (see MQTT5_FINDINGS.md section 3.3) plus
# the protocol Version enum, carried by the IO's Framing strategy (3.1, 3.2).
#
# These are exact-byte specs: the byte vectors are taken straight from the
# MQTT 5.0 spec's data representation section (1.5) so they catch a
# consistently-wrong-but-self-agreeing encoder.
describe MQTT::Protocol::IO do
  describe "Variable Byte Integer" do
    # §1.5.5: each byte encodes 7 bits, MSB is the continuation flag.
    # Boundaries: 0, 127 (1 byte), 128, 16383 (2), 16384, 2097151 (3),
    # 2097152, 268435455 (4).
    samples = {
                0 => Bytes[0x00],
              127 => Bytes[0x7F],
              128 => Bytes[0x80, 0x01],
           16_383 => Bytes[0xFF, 0x7F],
           16_384 => Bytes[0x80, 0x80, 0x01],
        2_097_151 => Bytes[0xFF, 0xFF, 0x7F],
        2_097_152 => Bytes[0x80, 0x80, 0x80, 0x01],
      268_435_455 => Bytes[0xFF, 0xFF, 0xFF, 0x7F],
    }

    samples.each do |value, bytes|
      it "writes #{value} as #{bytes}" do
        mio = IO::Memory.new
        io = MQTT::Protocol::IO.v3(mio)
        io.write_variable_byte_int(value)
        mio.to_slice.should eq bytes
      end

      it "reads #{bytes} as #{value}" do
        mio = IO::Memory.new
        mio.write bytes
        mio.rewind
        io = MQTT::Protocol::IO.v3(mio)
        io.read_variable_byte_int.should eq value
      end
    end

    it "raises PacketDecode on a 5-byte (overlong) value" do
      mio = IO::Memory.new
      mio.write Bytes[0x80u8, 0x80u8, 0x80u8, 0x80u8, 0x01u8]
      mio.rewind
      io = MQTT::Protocol::IO.v3(mio)
      expect_raises(MQTT::Protocol::Error::PacketDecode) do
        io.read_variable_byte_int
      end
    end

    it "rejects a non-minimal (overlong) encoding [MQTT-1.5.5-1]" do
      # 0x81 0x00 encodes the value 1 in two bytes; the minimal form is 0x01.
      # Accepting it desyncs the property consumed-counter, so the reader must
      # treat it as a Malformed Packet.
      mio = IO::Memory.new
      mio.write Bytes[0x81u8, 0x00u8]
      mio.rewind
      io = MQTT::Protocol::IO.v3(mio)
      expect_raises(MQTT::Protocol::Error::PacketDecode) do
        io.read_variable_byte_int
      end
    end
  end

  describe ".variable_byte_int_size" do
    # The inverse of the byte-count thresholds; used to precompute
    # remaining_length without serialising (3.8).
    it "returns 1 for 0..127" do
      MQTT::Protocol::IO.variable_byte_int_size(0).should eq 1
      MQTT::Protocol::IO.variable_byte_int_size(127).should eq 1
    end

    it "returns 2 for 128..16383" do
      MQTT::Protocol::IO.variable_byte_int_size(128).should eq 2
      MQTT::Protocol::IO.variable_byte_int_size(16_383).should eq 2
    end

    it "returns 3 for 16384..2097151" do
      MQTT::Protocol::IO.variable_byte_int_size(16_384).should eq 3
      MQTT::Protocol::IO.variable_byte_int_size(2_097_151).should eq 3
    end

    it "returns 4 for 2097152..268435455" do
      MQTT::Protocol::IO.variable_byte_int_size(2_097_152).should eq 4
      MQTT::Protocol::IO.variable_byte_int_size(268_435_455).should eq 4
    end
  end

  describe "Four Byte Integer" do
    it "writes a UInt32 big-endian" do
      mio = IO::Memory.new
      io = MQTT::Protocol::IO.v3(mio)
      io.write_four_byte_int(0xDEADBEEFu32)
      mio.to_slice.should eq Bytes[0xDE, 0xAD, 0xBE, 0xEF]
    end

    it "reads a UInt32 big-endian" do
      mio = IO::Memory.new
      mio.write Bytes[0x00u8, 0x00u8, 0x01u8, 0x00u8]
      mio.rewind
      io = MQTT::Protocol::IO.v3(mio)
      io.read_four_byte_int.should eq 256u32
    end

    it "round-trips the maximum value" do
      mio = IO::Memory.new
      io = MQTT::Protocol::IO.v3(mio)
      io.write_four_byte_int(UInt32::MAX)
      mio.rewind
      io.read_four_byte_int.should eq UInt32::MAX
    end
  end

  describe "UTF-8 String Pair" do
    it "writes key then value, each length-prefixed" do
      mio = IO::Memory.new
      io = MQTT::Protocol::IO.v3(mio)
      io.write_string_pair("name", "value")
      mio.to_slice.should eq Bytes[
        0x00, 0x04, 'n'.ord, 'a'.ord, 'm'.ord, 'e'.ord,
        0x00, 0x05, 'v'.ord, 'a'.ord, 'l'.ord, 'u'.ord, 'e'.ord,
      ]
    end

    it "reads a key/value tuple" do
      mio = IO::Memory.new
      io = MQTT::Protocol::IO.v3(mio)
      io.write_string_pair("k", "v")
      mio.rewind
      io.read_string_pair.should eq({"k", "v"})
    end
  end

  describe "remaining length is built on variable_byte_int" do
    # Regression for the bug noted in 3.3: write_remaining_length rejected
    # 2**28 while read accepted up to 2**28 - 1. Both must agree on the
    # 268_435_455 ceiling.
    it "accepts the maximum remaining length" do
      mio = IO::Memory.new
      io = MQTT::Protocol::IO.v3(mio)
      io.write_remaining_length(268_435_455)
      mio.to_slice.should eq Bytes[0xFF, 0xFF, 0xFF, 0x7F]
    end
  end
end

describe MQTT::Protocol::Version do
  it "maps levels to enum values" do
    MQTT::Protocol::Version::V3_1.value.should eq 3
    MQTT::Protocol::Version::V3_1_1.value.should eq 4
    MQTT::Protocol::Version::V5.value.should eq 5
  end

  it "is comparable by value" do
    (MQTT::Protocol::Version::V5 > MQTT::Protocol::Version::V3_1_1).should be_true
    (MQTT::Protocol::Version::V3_1 < MQTT::Protocol::Version::V3_1_1).should be_true
  end

  it "exposes the wire protocol name" do
    MQTT::Protocol::Version::V3_1.protocol_name.should eq "MQIsdp"
    MQTT::Protocol::Version::V3_1_1.protocol_name.should eq "MQTT"
    MQTT::Protocol::Version::V5.protocol_name.should eq "MQTT"
  end

  describe "on IO" do
    it "is fixed by the concrete IO type" do
      MQTT::Protocol::IO.v3(IO::Memory.new).version.should eq MQTT::Protocol::Version::V3_1_1
      MQTT::Protocol::IO.v5(IO::Memory.new).version.should eq MQTT::Protocol::Version::V5
    end

    it "is built for a version via IO.for" do
      mio = IO::Memory.new
      MQTT::Protocol::IO.for(MQTT::Protocol::Version::V5, mio)
        .version.should eq MQTT::Protocol::Version::V5
      MQTT::Protocol::IO.for(MQTT::Protocol::Version::V3_1_1, mio)
        .version.should eq MQTT::Protocol::Version::V3_1_1
    end
  end
end
