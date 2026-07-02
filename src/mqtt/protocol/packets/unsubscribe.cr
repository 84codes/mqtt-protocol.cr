module MQTT
  module Protocol
    struct Unsubscribe < Packet
      TYPE = 10u8
      getter packet_id, topics, properties

      def initialize(@topics : Array(String), @packet_id : UInt16,
                     @properties : UnsubscribeProperties = UnsubscribeProperties.new)
      end

      def remaining_length(version : MQTT::Protocol::Version) : UInt32
        len = 2 # packet id
        @topics.each do |topic|
          # This is the length of variable header (2 bytes) plus the length of the payload.
          len += (2 + topic.bytesize)
        end
        len += version.properties_bytesize(properties)
        len.to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags == 2, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length > 2, "protocol violation"

        packet_id = io.read_int
        properties = io.read_properties(UnsubscribeProperties)
        topics = Array(String).new
        while io.remaining_in_packet > 0
          topics << io.read_string
        end
        # The payload MUST contain at least one Topic Filter [MQTT-3.10.3-2].
        if topics.empty?
          raise Error::ProtocolError.new(0x82u8, "UNSUBSCRIBE must contain at least one topic filter")
        end
        self.new(topics, packet_id, properties)
      end

      def to_io(io)
        flags = 0b0010
        io.write_byte((TYPE << 4) | flags)
        io.write_remaining_length remaining_length(io.version)
        io.write_int(@packet_id)
        io.write_properties(properties)
        @topics.each do |topic|
          io.write_string(topic)
        end
      end
    end
  end
end
