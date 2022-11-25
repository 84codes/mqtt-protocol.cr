module MQTT
  module Protocol
    struct IO
      getter io

      def initialize(@io : ::IO, @byte_format = ::IO::ByteFormat::NetworkEndian)
      end

      forward_missing_to @io

      def read_byte
        @io.read_byte || raise ::IO::EOFError.new
      end

      def read_string(len : UInt16? = nil)
        len = read_int unless len
        str = @io.read_string(len)
        if str.includes?('\u0000') || !str.valid_encoding?
          raise MQTT::Protocol::Error::PacketDecode.new "Illformed UTF-8 string"
        end
        str
      end

      def read_int
        UInt16.from_io(@io, @byte_format)
      end

      def read_remaining_length
        multiplier : UInt32 = 1
        value : UInt32 = 0
        loop do
          b = @io.read_byte || raise ::IO::EOFError.new
          value += (b.to_u32 & 127u32) * multiplier
          break if b & 128 == 0
          multiplier *= 128
          raise Error::PacketDecode.new "invalid remaining length" if multiplier > 128*128*128
        end
        value
      end

      def read_bytes(len : Int? = nil)
        len = read_int unless len
        bytes = Bytes.new(len)
        @io.read_fully(bytes)
        bytes
      end

      def write_byte(b : UInt8)
        @io.write_byte b
      end

      def write_bytes(bytes : Bytes)
        write_int bytes.bytesize
        @io.write bytes
      end

      def write_bytes_raw(bytes : Bytes)
        @io.write bytes
      end

      def write_bytes(bytes : Nil)
        write_int 0
      end

      def write_string(str : String)
        write_int str.bytesize
        @io.write str.to_slice
      end

      def write_string(str : Nil)
        write_int 0
      end

      def write_int(int : Int)
        @io.write_bytes int.to_u16, @byte_format
      end

      def write_remaining_length(length)
        length < 2**28 || raise Error::PacketEncode.new
        loop do
          b = (length % 128).to_u8
          length = length // 128
          b = b | 128 if length > 0
          @io.write_byte b
          break if length <= 0
        end
      end
    end
  end
end
