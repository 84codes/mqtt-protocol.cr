module MQTT
  module Protocol
    struct Subscribe < Packet
      TYPE = 8u8

      record TopicFilter,
        topic : String,
        qos : UInt8,
        no_local : Bool = false,
        retain_as_published : Bool = false,
        retain_handling : UInt8 = 0u8 do
        def initialize(@topic : String, @qos : UInt8, @no_local : Bool = false,
                       @retain_as_published : Bool = false, @retain_handling : UInt8 = 0u8)
          raise ArgumentError.new("Topic must be at least 1 char long") if @topic.size < 1
          raise ArgumentError.new("Topic cannot be larger than 65535 bytes") if @topic.bytesize > 65535
          raise ArgumentError.new("Invalid Retain Handling: #{@retain_handling}") if @retain_handling > 2
          if @topic.count("#") > 1
            raise ArgumentError.new("There can only be one multi-level wildcard in a TopicFilter")
          end

          if !@topic.index("#").nil? && !(@topic.ends_with?("/#") || @topic.size == 1)
            raise ArgumentError.new("A multi-level wildcard TopicFilter must have '#' as the last character")
          end

          levels = @topic.split("/")
          plus_levels = levels.select do |level|
            level.count('+').positive? && level.size > 1
          end
          return if plus_levels.empty?
          raise ArgumentError.new("A single-level wildcard TopicFilter most cover an entire level on its own.")
        end

        def no_local?
          @no_local
        end

        def retain_as_published?
          @retain_as_published
        end
      end

      getter topic_filters, packet_id, properties

      def initialize(@topic_filters : Array(TopicFilter), @packet_id : UInt16,
                     @properties : SubscribeProperties = SubscribeProperties.new)
      end

      def remaining_length(version : MQTT::Protocol::Version) : UInt32
        len = 2 # packet id
        @topic_filters.each do |topic_filter|
          # 2 is UInt16 prefix topic length, the topic bytesize, 1 is the options byte
          len += (2 + topic_filter.topic.bytesize + 1)
        end
        len += version.properties_bytesize(properties)
        len.to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags == 2, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length > 2, "protocol violation"
        io.ensure_packet_budget(remaining_length)
        packet_id = io.read_int

        # The subscription-identifier-0 rejection (3.8.2.1.2) is declared as
        # the range on SubscribeProperties#subscription_identifier and enforced
        # by the generated decoder.
        properties = io.read_properties(SubscribeProperties)

        topic_filters = Array(TopicFilter).new
        while io.remaining_in_packet > 0
          topic = io.read_string
          options = io.read_byte
          qos = options & 0b0000_0011u8
          decode_assert qos < 3, "Malformed packet"
          io.validate_subscription_options(options)
          no_local = options.bit(2) == 1
          retain_as_published = options.bit(3) == 1
          retain_handling = (options & 0b0011_0000u8) >> 4
          topic_filters << TopicFilter.new(topic, qos, no_local, retain_as_published, retain_handling)
        end
        # The payload MUST contain at least one Topic Filter / Options pair
        # [MQTT-3.8.3-2]; on v5 an empty properties section otherwise slips
        # a zero-filter packet past the length check.
        if topic_filters.empty?
          raise Error::ProtocolError.new(0x82u8, "SUBSCRIBE must contain at least one topic filter")
        end
        new(topic_filters, packet_id, properties)
      rescue ex : ArgumentError
        raise Error::PacketDecode.new(ex.message)
      end

      def to_io(io)
        flags = 0b0010
        io.write_byte((TYPE << 4) | flags)
        io.write_remaining_length remaining_length(io.version)
        io.write_int(@packet_id)
        io.write_properties(properties)

        if @topic_filters.empty?
          raise MQTT::Protocol::Error::PacketEncode.new("Subscribe Packet must contain TopicFilters")
        end

        @topic_filters.each do |topic_filter|
          io.write_string(topic_filter.topic)
          options = topic_filter.qos
          options |= 0b0000_0100u8 if topic_filter.no_local?
          options |= 0b0000_1000u8 if topic_filter.retain_as_published?
          options |= (topic_filter.retain_handling << 4)
          io.write_byte(options)
        end
      end
    end
  end
end
