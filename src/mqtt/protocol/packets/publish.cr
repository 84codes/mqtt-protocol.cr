require "./packets"

module MQTT
  module Protocol
    struct Publish < Packet
      TYPE = 3u8

      getter payload, qos, packet_id, properties
      getter? dup, retain

      # The topic is stored as raw bytes: PUBLISH is the hot data-plane packet,
      # and a broker routing/forwarding it never needs the decoded String. This
      # skips a per-message allocation and UTF-8 validation pass. `topic` decodes
      # to a String for convenience (back-compat); `topic_bytes` is the raw,
      # allocation-free form the hot path should prefer.
      def topic : String
        String.new(@topic)
      end

      def topic_bytes : Bytes
        @topic
      end

      def initialize(@topic : Bytes, @payload : Bytes, @packet_id : UInt16?, @dup : Bool,
                     @qos : UInt8, @retain : Bool, @properties : PublishProperties = PublishProperties.new)
        raise ArgumentError.new("QoS must be 0, 1 or 2") if @qos > 2
        if @topic.any? { |b| b == 0x23u8 || b == 0x2bu8 } # '#' / '+'
          raise ArgumentError.new("Topic cannot contain wildcard")
        end
        raise ArgumentError.new("Topic cannot be larger than 65535 bytes") if @topic.bytesize > 65535
        raise ArgumentError.new("DUP must be 0 for QoS 0 messages") if dup? && qos.zero?
        # Empty topic is version-gated at decode (legal in v5 with a Topic
        # Alias), so it is not rejected here.
      end

      # Convenience for callers that hold the topic as a `String`; stores its
      # UTF-8 bytes.
      def self.new(topic : String, payload : Bytes, packet_id : UInt16?, dup : Bool,
                   qos : UInt8, retain : Bool, properties : PublishProperties = PublishProperties.new)
        new(topic.to_slice, payload, packet_id, dup, qos, retain, properties)
      end

      def remaining_length(version : MQTT::Protocol::Version) : UInt32
        len = (2 + @topic.bytesize) + payload.bytesize
        len += 2 if qos.positive? # packet_id
        len += version.properties_bytesize(properties)
        len.to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length : UInt32)
        dup = flags.bit(3) > 0
        retain = flags.bit(0) > 0
        qos = (flags & 0b00000110u8) >> 1
        decode_assert qos < 3, "invalid qos: #{qos}"
        topic = io.read_bytes
        remaining_length = io.consume(remaining_length, 2 + topic.bytesize)
        if qos.positive?
          packet_id = io.read_int
          remaining_length = io.consume(remaining_length, 2)
        else
          decode_assert dup == false, "DUP must be 0 for QoS 0 messages"
        end
        # Empty topic is only legal in v5 (resolved via a Topic Alias).
        decode_assert io.allow_empty_topic? || !topic.empty?, "empty publish topic"
        properties, consumed = io.read_properties(PublishProperties, remaining_length)
        remaining_length = io.consume(remaining_length, consumed)
        payload = io.read_bytes(remaining_length)
        self.new(topic, payload, packet_id, dup, qos, retain, properties)
      rescue ex : ArgumentError
        raise MQTT::Protocol::Error::PacketDecode.new(ex.message)
      end

      def to_io(io)
        flags = 0u8
        flags |= 0b0000_1000u8 if dup?
        flags |= 0b0000_0001u8 if retain?
        flags |= (0b0000_0110u8 & (qos << 1)) if qos.positive?
        io.write_byte((TYPE << 4) | flags)
        io.write_remaining_length remaining_length(io.version)
        io.write_bytes @topic
        io.write_int packet_id.not_nil!("packet_id must be set if QoS > 0") if qos.positive?
        io.write_properties(properties)
        io.write_bytes_raw(payload)
      end
    end
  end
end
