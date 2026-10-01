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

      # The Clean Start flag (3.1.2.4). The same bit as v3's Clean Session; the
      # session lifetime that v3 also tied to it is in
      # `properties.session_expiry_interval`.
      def clean_start? : Bool
        @clean_session
      end

      @[Deprecated("Use `#clean_start?` and `properties.session_expiry_interval`")]
      def clean_session? : Bool
        @clean_session
      end

      def initialize(@client_id, @clean_session, @keepalive, @username, @password, @will,
                     @version : Version = Version::V3_1_1, @properties = ConnectProperties.new)
        # Unknown is an IO state; a CONNECT on the wire always names a real level.
        raise ArgumentError.new("CONNECT needs a known protocol version") if @version.unknown?
        # v5 allows a Password without a User Name (3.1.2.9); v3.1.1 forbids
        # it ([MQTT-3.1.2-22 v3.1.1]), and there is no flag encoding for it in v3.
        if @password && @username.nil? && !@version.v5?
          raise ArgumentError.new("password without username requires MQTT 5.0")
        end
        # A v3 session without Clean Session lasts until a clean connect, which
        # v5 spells as an expiry that never runs out (3.1.2.11.2). Only filled
        # in when absent: v3 cannot carry the property, so this is the v5 view
        # of the flag, not something that goes on the wire.
        if !@version.v5? && !@clean_session && @properties.session_expiry_interval?.nil?
          @properties.session_expiry_interval = UInt32::MAX
        end
      end

      # Return a copy with the given fields changed and the rest carried over, so
      # a consumer (e.g. assigning a client id server-side) can't silently drop
      # version/properties by re-listing the constructor. Mirrors `record`'s
      # `copy_with`, hand-written because Connect is a plain `struct < Packet`.
      def copy_with(client_id = @client_id, clean_session = @clean_session,
                    keepalive = @keepalive, username = @username, password = @password,
                    will = @will, version = @version, properties = @properties)
        Connect.new(client_id, clean_session, keepalive, username, password, will, version, properties)
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
        end
        if pwd = @password
          len += 2 + pwd.size
        end
        len.to_u32
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, remaining_length)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags
        io.ensure_packet_budget(remaining_length.to_u32)

        # Field reads are bounded by the IO's packet byte budget, so a tiny
        # packet can't declare a huge field (client id / username / password)
        # and drive a read past its boundary.
        # The name is only compared, never kept, so read it into a stack buffer
        # sized for the longest valid name ("MQIsdp") instead of a heap String.
        protocol_buf = uninitialized UInt8[6]
        protocol_len = io.read_int
        if protocol_len > protocol_buf.size
          raise Error::UnacceptableProtocolVersion.new("invalid protocol name length: #{protocol_len}")
        end
        protocol = protocol_buf.to_slice[0, protocol_len]
        io.read_fully(protocol)
        version = Version.from_protocol(protocol, io.read_byte)
        # The protocol level is what reveals the version; switch the IO's framing
        # here so the rest of CONNECT, every later packet, and any CONNACK
        # rejecting this very CONNECT all use it.
        unless io.negotiate(version)
          raise Error::ProtocolError.new(0x82u8, "#{version} CONNECT on a #{io.version} connection")
        end

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

        # v3.1.1 forbids the password flag without the username flag
        # ([MQTT-3.1.2-22 v3.1.1]); v5 explicitly allows it (3.1.2.9).
        unless version.v5?
          decode_assert has_username || !has_password, "Password cannot be set without a username"
        end

        keepalive = io.read_int

        properties = io.read_properties(ConnectProperties)

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

        # [MQTT-3.1.3-7]: v3.1.1 only takes an empty client id with Clean
        # Session. v5 dropped the condition (3.1.3.1): the server assigns an id.
        if client_id.empty? && !version.v5?
          decode_assert clean_session == true, Error::IdentifierRejected
        end

        if has_will
          will = Will.from_io(io, will_qos, will_retain)
        end
        if has_username
          username = io.read_string
        end
        if has_password
          password = io.read_bytes
        end
        # Exact consumption of remaining_length (section 2.1.4) is enforced
        # centrally by the dispatcher's finish_packet.

        new(client_id, clean_session, keepalive, username, password, will, version, properties)
      end

      def to_io(io)
        io.validate_outbound_packet_type(TYPE)
        # CONNECT establishes the version on an IO that has none yet; one
        # already negotiated to another version refuses before any byte is written.
        unless io.negotiate(@version)
          raise Error::PacketEncode.new("cannot write a #{@version} CONNECT on a #{io.version} connection")
        end
        connect_flags = 0u8
        if w = will
          connect_flags |= 0b0000_0100u8
          connect_flags |= 0b0010_0000u8 if w.retain?
          connect_flags |= ((w.qos & 0b0000_0011u8) << 3)
        end
        connect_flags |= 0b1000_0000u8 if username
        # Password can be present without a username on v5 (3.1.2.9); the
        # constructor rejects that combination for v3.
        connect_flags |= 0b0100_0000u8 if password
        connect_flags |= 0b0000_0010u8 if clean_start?
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
        end
        if pwd = password
          io.write_bytes pwd
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

      def self.from_io(io : MQTT::Protocol::IO, qos : UInt8, retain : Bool) : Will
        # In v5 the Will Properties precede the Will Topic on the wire.
        properties = io.read_properties(WillProperties)
        topic = io.read_string
        payload = io.read_bytes
        new(topic, payload, qos, retain, properties)
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
