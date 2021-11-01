module MQTT
  module Protocol
    struct SubAck < Packet
      TYPE = 9u8
      enum ReturnCode : UInt8
        QoS0    =   0
        QoS1    =   1
        QoS2    =   2
        Failure = 128

        def self.from_int(value)
          case value
          when 0
            QoS0
          when 1
            QoS1
          when 2
            QoS2
          when 128
            Failure
          else
            raise Error::PacketDecode.new "invalid return code #{value}"
          end
        end
      end

      getter return_codes, packet_id

      def initialize(@return_codes : Array(ReturnCode), @packet_id : UInt16)
        @remaining_length += @return_codes.size
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length > 2, "protocol violation"
        packet_id = io.read_int
        bytes_to_read = remaining_length - 2
        return_codes = Array(ReturnCode).new
        while bytes_to_read > 0
          return_code = io.read_byte
          return_codes << ReturnCode.from_int(return_code)
          bytes_to_read -= 1
        end
        self.new(return_codes, packet_id)
      end

      def to_io(io)
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length
        io.write_int(@packet_id)
        @return_codes.each do |return_code|
          io.write_byte(return_code.to_u8)
        end
      end
    end
  end
end
