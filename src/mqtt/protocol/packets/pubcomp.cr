module MQTT
  module Protocol
    struct PubComp < Packet
      TYPE = 7u8

      getter packet_id

      def initialize(@packet_id : UInt16)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        # PUBCOMP's low nibble is reserved and must be 0 (MQTT 3.1.1 3.7.1).
        # PUBREL, SUBSCRIBE and UNSUBSCRIBE are the ones that carry 0b0010.
        #
        # 2 is accepted as well as 0 because this library wrote 0b0010 up to
        # and including v0.3.1, so a peer built on an older version is still
        # sending it. Only 0 is ever written, see `to_io`.
        decode_assert (flags.zero? || flags == 2), MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length == 2, sprintf("invalid length: %d", remaining_length)
        packet_id = io.read_int
        new(packet_id)
      end

      def to_io(io)
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length
        io.write_int(packet_id)
      end
    end
  end
end
