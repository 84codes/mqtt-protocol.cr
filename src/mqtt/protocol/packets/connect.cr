require "./packets"

module MQTT
  module Protocol
    struct Connect < Packet
      TYPE = 1_u8

      @client_id : String
      @clean_session : Bool
      @keepalive : UInt16
      @username : String?
      @password : Bytes?
      @will : Will?
      @version : Version
      @properties : ConnectProperties

      getter client_id, keepalive, username, password, will, version, properties
      getter? clean_session

      def initialize(@client_id, @clean_session, @keepalive, @username, @password, @will,
                     @version : Version = Version::V3_1_1, @properties = ConnectProperties.new)
      end

      # CONNECT carries its own protocol version, so its framing follows
      # @version regardless of the argument (which exists for the base signature).
      def remaining_length(version : Version) : UInt32
        # Variable header: protocol name (str) + protocol level (byte) +
        # connect flags (byte) + keep alive (int)
        len = 2 + @version.protocol_name.bytesize + 1 + 1 + 2
        len += @version.properties_bytesize(@properties)
        # Payload: client id, [will], [username], [password]
        len += 2 + @client_id.bytesize
        if w = @will
          len += w.bytesize(@version)
        end
        if u = @username
          len += 2 + u.bytesize
          if pwd = @password
            len += 2 + pwd.size
          end
        end
        len.to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags

        protocol_len = io.read_int
        protocol = io.read_string(protocol_len)
        version_byte = io.read_byte

        # MQIsdp is MQTT 3.1, MQTT level 4 is 3.1.1, MQTT level 5 is 5.0
        version =
          case {protocol, version_byte}
          when {"MQTT", 0x04u8}   then Version::V3_1_1
          when {"MQTT", 0x05u8}   then Version::V5
          when {"MQIsdp", 0x03u8} then Version::V3_1
          else
            raise Error::UnacceptableProtocolVersion.new("invalid protocol: #{protocol.inspect} level #{version_byte}")
          end
        # The protocol level is what reveals the version; reframe so the rest of
        # CONNECT (and the IO the caller keeps for later packets) uses it.
        io = io.reframe(version)

        connect_flags = io.read_byte
        decode_assert connect_flags.bit(0) == 0, "reserved connect flag set"
        clean_session = connect_flags.bit(1) == 1
        has_will = connect_flags.bit(2) == 1
        unless has_will
          will_flags = (connect_flags & 0b00111000)
          decode_assert will_flags.zero?, "Invalid will flags, must be zero"
        end
        will_qos = (connect_flags & 0b00011000) >> 3
        decode_assert will_qos < 3, "invalid will qos: #{will_qos}"

        will_retain = connect_flags.bit(5) == 1
        has_password = connect_flags.bit(6) == 1
        has_username = connect_flags.bit(7) == 1

        decode_assert has_username || !has_password, "Password cannot be set without a username"

        keepalive = io.read_int

        # CONNECT is not consume-tracked, so the whole packet's remaining length
        # is a (loose) upper bound on the property section - enough to stop a
        # small packet declaring an oversized section.
        properties, _ = io.read_properties(ConnectProperties, remaining_length.to_u32)

        client_id_len = io.read_int
        # Maximum client id length is version-specific. v3.1 (MQIsdp) capped it
        # at 23 bytes; v3.1.1 and v5 leave the maximum to the server, bounded
        # only by the 2-byte wire length prefix (65535) and max_packet_size
        # (enforced in read_string). Length/charset policy beyond that is the
        # consumer's to decide.
        if version.v3_1? && client_id_len > 23
          raise Error::IdentifierRejected.new("client id too long: #{client_id_len} > 23")
        end
        client_id = io.read_string(client_id_len)

        if client_id.to_s.empty?
          decode_assert clean_session == true, Error::IdentifierRejected
        end

        will = has_will ? Will.from_io(io, will_qos, will_retain, remaining_length.to_u32) : nil
        username = io.read_string if has_username
        password = io.read_bytes if has_password

        self.new(client_id, clean_session, keepalive, username, password, will, version, properties)
      end

      # ameba:disable Metrics/CyclomaticComplexity
      def to_io(io)
        # CONNECT establishes the version, so frame on @version regardless of
        # the IO handed in (the caller switches to a matching IO afterwards).
        io = io.reframe(@version)
        connect_flags = 0u8
        if w = will
          connect_flags |= 0b0000_0100u8
          connect_flags |= 0b0010_0000u8 if w.retain?
          connect_flags |= ((w.qos & 0b0000_0011u8) << 3)
        end
        if u = username
          connect_flags |= 0b1000_0000u8
          if password
            connect_flags |= 0b0100_0000u8
          end
        end
        connect_flags |= 0b0000_0010u8 if clean_session?
        io.write_byte(TYPE << 4)
        io.write_remaining_length remaining_length(@version)
        io.write_string @version.protocol_name
        io.write_byte @version.value
        io.write_byte connect_flags
        io.write_int keepalive
        io.write_properties(@properties)
        io.write_string client_id
        if w = will
          w.to_io(io)
        end
        if u = username
          io.write_string u
          if pwd = password
            io.write_bytes pwd
          end
        end
      end
    end

    struct Will
      getter topic, payload, qos, properties
      getter? retain

      def initialize(@topic : String, @payload : Bytes, @qos : UInt8, @retain : Bool,
                     @properties : WillProperties = WillProperties.new)
        raise ArgumentError.new("Topic cannot contain wildcard") if @topic.matches?(/[#+]/)
      end

      def self.from_io(io : MQTT::Protocol::IO, qos : UInt8, retain : Bool, remaining : UInt32)
        # In v5 the Will Properties precede the Will Topic on the wire.
        properties, _ = io.read_properties(WillProperties, remaining)
        topic = io.read_string
        payload = io.read_bytes
        self.new(topic, payload, qos, retain, properties)
      rescue ex : ArgumentError
        raise MQTT::Protocol::Error::PacketDecode.new(ex.message)
      end

      def to_io(io)
        io.write_properties(@properties)
        io.write_string topic
        io.write_bytes payload
      end

      def bytesize(version : Version = Version::V3_1_1) : Int32
        size = 2 + topic.bytesize + 2 + payload.size
        size += version.properties_bytesize(@properties)
        size
      end
    end
  end
end
