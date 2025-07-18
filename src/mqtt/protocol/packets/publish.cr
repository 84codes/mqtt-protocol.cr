require "./packets"

module MQTT
  module Protocol
    struct Publish < Packet
      TYPE = 3u8

      getter topic, payload, qos, packet_id, remaining_length
      getter? dup, retain

      def initialize(@topic : String, @payload : Bytes, @packet_id : UInt16?, @dup : Bool, @qos : UInt8, @retain : Bool)
        raise ArgumentError.new("QoS must be 0, 1 or 2") if @qos > 2
        raise ArgumentError.new("Topic cannot contain wildcard") if @topic.matches?(/[#+]/)
        raise ArgumentError.new("Topic must be between atleast 1 char long") if @topic.size < 1
        raise ArgumentError.new("Topic cannot be larger than 65535 bytes") if @topic.bytesize > 65535
        raise ArgumentError.new("DUP must be 0 for QoS 0 messages") if dup? && qos.zero?
        @remaining_length = 0
        @remaining_length += (2 + topic.bytesize) + payload.bytesize
        @remaining_length += 2 if qos.positive? # packet_id
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        dup = flags.bit(3) > 0
        retain = flags.bit(0) > 0
        qos = (flags & 0b00000110u8) >> 1
        decode_assert qos < 3, "invalid qos: #{qos}"
        topic = io.read_string
        remaining_length -= (2 + topic.bytesize)
        if qos.positive?
          packet_id = io.read_int
          remaining_length -= 2
        else
          decode_assert dup == false, "DUP must be 0 for QoS 0 messages"
        end
        payload = io.read_bytes(remaining_length)
        self.new(topic, payload, packet_id, dup, qos, retain)
      rescue ex : ArgumentError
        raise MQTT::Protocol::Error::PacketDecode.new(ex.message)
      end

      def to_io(io)
        flags = 0u8
        flags |= 0b0000_1000u8 if dup?
        flags |= 0b0000_0001u8 if retain?
        flags |= (0b0000_0110u8 & (qos << 1)) if qos.positive?
        io.write_byte((TYPE << 4) | flags)
        io.write_remaining_length remaining_length
        io.write_string topic
        io.write_int packet_id.not_nil! if qos.positive?
        io.write_bytes_raw(payload)
      end
    end
  end
end
