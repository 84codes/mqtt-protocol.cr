module MQTT
  module Protocol
    struct UnsubAck < Packet
      TYPE = 11u8

      getter packet_id

      def initialize(@packet_id : UInt16)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length == 2, "invalid length"
        packet_id = io.read_int
        self.new(packet_id)
      end

      def to_io(io)
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length
        io.write_int(packet_id)
      end
    end
  end
end
