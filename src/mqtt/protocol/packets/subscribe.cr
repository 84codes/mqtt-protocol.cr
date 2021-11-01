module MQTT
  module Protocol
    struct Subscribe < Packet
      TYPE = 8u8
      record TopicFilter, topic : String, qos : UInt8 do
        def initialize(@topic : String, @qos : UInt8)
          raise ArgumentError.new("Topic must be at least 1 char long") if @topic.size < 1
          raise ArgumentError.new("Topic cannot be larger than 65535 bytes") if @topic.bytesize > 65535
          if @topic.count("#") > 1
            raise ArgumentError.new("There can only be one multi-level wildcard in a TopicFilter")
          end

          if !@topic.index("#").nil? && !(@topic.ends_with?("/#") || @topic.size == 1)
            raise ArgumentError.new("A multi-level wildcard TopicFilter
                                     must have '#' as the last character")
          end

          levels = @topic.split("/")
          plus_levels = levels.select do |level|
            level.count('+').positive? && level.size > 1
          end
          return if plus_levels.empty?
          raise ArgumentError.new("A single-level wildcard TopicFilter most cover an entire level
                                   on its own.")
        end
      end

      getter topic_filters, packet_id

      def initialize(@topic_filters : Array(TopicFilter), @packet_id : UInt16)
        @topic_filters.each do |topic_filter|
          # 2 is Int32 prefix topic length, the topic bytesize, 1 is the QoS
          @remaining_length += (2 + topic_filter.topic.bytesize + 1)
        end
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags == 2, MQTT::Protocol::Error::InvalidFlags, flags
        decode_assert remaining_length > 2, "protocol violation"
        packet_id = io.read_int

        bytes_to_read = remaining_length - 2
        topic_filters = Array(TopicFilter).new
        while bytes_to_read > 0
          topic = io.read_string
          qos = io.read_byte
          decode_assert qos < 3, "Malformed packet"
          topic_filters << TopicFilter.new(topic, qos)
          # 2 is UInt16 prefix topic length, the topic bytesize, 1 is the QoS
          bytes_to_read -= (2 + topic.bytesize + 1)
        end
        self.new(topic_filters, packet_id)
      rescue ex : ArgumentError
        raise Error::PacketDecode.new(ex.message)
      end

      def to_io(io)
        flags = 0b0010
        io.write_byte((TYPE << 4) | flags)
        io.write_remaining_length remaining_length
        io.write_int(@packet_id)

        if @topic_filters.empty?
          raise MQTT::Protocol::Error::PacketEncode.new("Subscribe Packet must contain TopicFilters")
        end

        @topic_filters.each do |topic_filter|
          io.write_string(topic_filter.topic)
          io.write_byte(topic_filter.qos)
        end
      end
    end
  end
end
