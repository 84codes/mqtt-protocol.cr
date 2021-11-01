module MQTT
  module Protocol
    struct Unsubscribe < Packet
      TYPE = 10u8
      getter packet_id, topics

      def initialize(@topics : Array(String), @packet_id : UInt16)
        @topics.each do |topic|
          # This is the length of variable header (2 bytes) plus the length of the payload.
          @remaining_length += (2 + topic.bytesize)
        end
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        decode_assert flags == 2, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length > 2, "protocol violation"

        packet_id = io.read_int
        bytes_to_read = remaining_length - 2
        topics = Array(String).new
        while bytes_to_read > 0
          topic = io.read_string
          topics << topic
          bytes_to_read -= (2 + topic.bytesize)
        end
        self.new(topics, packet_id)
      end

      def to_io(io)
        flags = 0b0010
        io.write_byte((TYPE << 4) | flags)
        io.write_remaining_length remaining_length
        io.write_int(@packet_id)
        @topics.each do |topic|
          io.write_string(topic)
        end
      end
    end
  end
end
