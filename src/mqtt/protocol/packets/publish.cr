require "./packets"

module MQTT
  module Protocol
    struct Publish < Packet
      TYPE = 3u8

      getter payload, qos, packet_id, properties
      getter? dup, retain

      # The topic is stored as raw bytes: PUBLISH is the hot data-plane packet,
      # and a broker routing/forwarding it never needs the decoded String. It
      # is still validated (wildcards, U+0000, UTF-8 well-formedness) in one
      # allocation-free byte scan - see validate_topic. `topic` decodes to a
      # String for convenience (back-compat); `topic_bytes` is the raw,
      # allocation-free form the hot path should prefer.
      #
      # NOTE: despite looking like a plain getter, this allocates a new String
      # (copying the topic bytes) on EVERY call - memoization is unreliable on
      # a struct (the memo dies with each copy). Call it once and hold the
      # result, or use `topic_bytes` on hot paths.
      def topic : String
        String.new(@topic)
      end

      def topic_bytes : Bytes
        @topic
      end

      def initialize(@topic : Bytes, @payload : Bytes, @packet_id : UInt16?, @dup : Bool,
                     @qos : UInt8, @retain : Bool, @properties : PublishProperties = PublishProperties.new)
        raise ArgumentError.new("QoS must be 0, 1 or 2") if @qos > 2
        validate_topic(@topic)
        raise ArgumentError.new("Topic cannot be larger than 65535 bytes") if @topic.bytesize > 65535
        raise ArgumentError.new("DUP must be 0 for QoS 0 messages") if dup? && qos.zero?
        # Empty topic is version-gated at decode (legal in v5 with a Topic
        # Alias), so it is not rejected here.
      end

      # Rejects wildcard bytes ('#'/'+', [MQTT-3.3.2-2]), U+0000
      # ([MQTT-1.5.4-2]) and ill-formed UTF-8 ([MQTT-3.3.2-1] via
      # [MQTT-1.5.4-1]). Topics are almost always pure ASCII, which one cheap
      # byte scan fully validates without allocating; only a topic that
      # actually contains non-ASCII bytes pays a String allocation for the
      # stdlib's UTF-8 validation.
      private def validate_topic(bytes : Bytes) : Nil
        ascii = true
        bytes.each do |b|
          case b
          when 0x23u8, 0x2Bu8 # '#' / '+'
            raise ArgumentError.new("Topic cannot contain wildcard")
          when 0x00u8
            raise ArgumentError.new("Topic cannot contain U+0000")
          else
            ascii = false if b >= 0x80u8
          end
        end
        return if ascii
        unless Unicode.valid?(bytes)
          raise ArgumentError.new("Topic must be well-formed UTF-8")
        end
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
        io.ensure_packet_budget(remaining_length)
        topic = io.read_bytes
        if qos.positive?
          packet_id = io.read_int
        else
          decode_assert dup == false, "DUP must be 0 for QoS 0 messages"
        end
        properties = io.read_properties(PublishProperties)
        if topic.empty?
          # A zero-length Topic Name is only legal on v5, and only when it is
          # resolved via a Topic Alias (the unnumbered Protocol Error
          # sentence in 3.3.2.1).
          decode_assert io.allow_empty_topic?, "empty publish topic"
          unless properties.topic_alias
            raise Error::ProtocolError.new(0x82u8, "empty topic without a topic alias")
          end
        end
        # The payload is whatever the packet has left.
        payload = io.read_bytes(io.remaining_in_packet)
        self.new(topic, payload, packet_id, dup, qos, retain, properties)
      rescue ex : ArgumentError
        raise MQTT::Protocol::Error::PacketDecode.new(ex.message)
      end

      def to_io(io)
        # Mirror of the decode rule: an empty topic can only go on the wire in
        # v5 with a Topic Alias to resolve it (the unnumbered Protocol Error
        # sentence in 3.3.2.1).
        if @topic.empty? && !(io.allow_empty_topic? && properties.topic_alias)
          raise MQTT::Protocol::Error::PacketEncode.new("empty topic requires a v5 topic alias")
        end
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
