require "./io"

private macro decode_assert(condition, err)
  {% if (err.class_name == "StringLiteral" || err.class_name == "StringInterpolation") %}
    ({{condition}} || raise Error::PacketDecode.new {{err}})
  {% else %}
    ({{condition}} || raise {{err}}.new)
  {% end %}
end

module MQTT
  module Protocol
    alias Flags = UInt8

    abstract struct Packet
      abstract def to_io(io : MQTT::Protocol::IO)

      def self.from_io(io : ::IO)
        from_io MQTT::Protocol::IO.new(io)
      end

      def self.from_io(io : MQTT::Protocol::IO)
        first_byte = io.read_byte || raise(::IO::EOFError.new)
        type = first_byte >> 4
        flags = first_byte & 0b00001111
        remaining_length = io.read_remaining_length
        packet =
          case type
          when Connect::TYPE     then Connect.from_io(io, flags, remaining_length)
          when Connack::TYPE     then Connack.from_io(io, flags, remaining_length)
          when Publish::TYPE     then Publish.from_io(io, flags, remaining_length)
          when Unsubscribe::TYPE then Unsubscribe.from_io(io, flags, remaining_length)
          when UnsubAck::TYPE    then UnsubAck.from_io(io, flags, remaining_length)
          when PingReq::TYPE     then PingReq.from_io(io, flags, remaining_length)
          when PingResp::TYPE    then PingResp.from_io(io, flags, remaining_length)
          when Disconnect::TYPE  then Disconnect.from_io(io, flags, remaining_length)
          else
            decode_assert false, "invalid packet type"
          end
        packet
      end
    end

    struct Connect < Packet
      TYPE = 1_u8

      @client_id : String?
      @clean_session : Bool
      @keepalive : UInt16
      @username : String?
      @password : Bytes?
      @will : Will?

      getter client_id, keepalive, username, password, will
      getter? clean_session

      def initialize(@client_id, @clean_session, @keepalive, @username, @password, @will)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, _remaining_length)
        decode_assert flags.zero?, "invalid flags"

        protocol_len = io.read_int
        decode_assert protocol_len == 4, "invalid protocol length"

        protocol = io.read_string(protocol_len)
        decode_assert protocol == "MQTT", "invalid protocol: #{protocol.inspect}"

        version = io.read_byte
        decode_assert version == 0x04, Error::UnacceptableProtocolVersion

        connect_flags = io.read_byte
        decode_assert connect_flags.bit(0) == 0, "reserved connect flag set"
        clean_session = connect_flags.bit(1) == 1
        has_will = connect_flags.bit(2) == 1
        will_qos = (connect_flags & 0b00011000) >> 3
        will_retain = connect_flags.bit(5) == 1
        has_password = connect_flags.bit(6) == 1
        has_username = connect_flags.bit(7) == 1

        keepalive = io.read_int

        client_id_len = io.read_int
        decode_assert client_id_len < 256, "client id too long, #{client_id_len} > 255"
        client_id = io.read_string(client_id_len)

        if client_id.to_s.empty?
          decode_assert clean_session == true, "must set clean session if client_id is empty"
          client_id = "gen-#{Random::Secure.urlsafe_base64(24)}"
        end

        will = has_will ? Will.from_io(io, will_qos, will_retain) : nil
        username = io.read_string if has_username
        password = io.read_bytes if has_password

        self.new(client_id, clean_session, keepalive, username, password, will)
      end

      def to_io(io)
        # Remaining length is at least 10:
        # protocol name (str) + protocol version (byte) + connect flags (byte) + keep alive (int)
        remaining_length = 10
        connect_flags = 0u8
        if c = client_id
          remaining_length += sizeof(UInt16)
          remaining_length += c.bytesize
        end
        if w = will
          connect_flags |= 0b0000_0100u8
          connect_flags |= 0b0010_0000u8 if w.retain?
          connect_flags |= ((w.qos & 0b0000_0011u8) << 3)
          remaining_length += sizeof(UInt16)
          remaining_length += w.topic.bytesize
          remaining_length += sizeof(UInt16)
          remaining_length += w.body.bytesize
        end
        if u = username
          connect_flags |= 0b1000_0000u8
          remaining_length += sizeof(UInt16)
          remaining_length += u.bytesize
        end
        if pwd = password
          connect_flags |= 0b0100_0000u8
          remaining_length += sizeof(UInt16)
          remaining_length += pwd.bytesize
        end
        connect_flags |= 0b0000_0010u8 if clean_session?
        io.write_byte (TYPE << 4)
        io.write_remaining_length remaining_length
        io.write_string "MQTT"
        io.write_byte 4u8 # "protocol version"
        io.write_byte connect_flags
        io.write_int keepalive
        io.write_string c if c
        w.to_io(io) if w
        io.write_string u if u
        io.write_bytes pwd if pwd
      end
    end

    struct Will
      getter topic, body, qos
      getter? retain

      def initialize(@topic : String, @body : Bytes, @qos : UInt8, @retain : Bool)
      end

      def self.from_io(io : MQTT::Protocol::IO, qos : UInt8, retain : Bool)
        topic = io.read_string
        body = io.read_bytes
        self.new(topic, body, qos, retain)
      end

      def to_io(io)
        io.write_string topic
        io.write_bytes body
      end
    end

    struct Connack < Packet
      enum ReturnCode : UInt8
        Accepted                    = 0
        UnacceptableProtocolVersion = 1
        IdentifierRejected          = 2
        ServerUnavailable           = 3
        BadCredentials              = 4
        NotAuthorized               = 5
      end

      TYPE = 2u8

      getter return_code
      getter? session_present

      def initialize(@session_present : Bool, @return_code : ReturnCode)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags.zero?, "invalid flags"

        connack_flags = io.read_byte
        decode_assert (connack_flags & 0b11111110).zero?, "invalid connack flags"
        session_present = (connack_flags & 1u8) > 0

        return_code = io.read_byte
        decode_assert return_code < 6, "invalid return code"

        self.new(session_present, ReturnCode.new(return_code))
      end

      def to_io(io)
        io.write_byte (TYPE << 4)
        io.write_remaining_length 2
        io.write_byte session_present? ? 1u8 : 0u8
        io.write_byte return_code.to_u8
      end
    end

    struct Publish < Packet
      TYPE = 3u8

      getter topic, body, qos, packet_id
      getter? dup, retain

      def initialize(@topic : String, @body : Bytes, @packet_id : UInt16?, @dup : Bool, @qos : UInt8, @retain : Bool)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        dup = flags.bit(3) > 0
        retain = flags.bit(0) > 0
        qos = (flags & 0b00000110u8) >> 1
        decode_assert qos < 3, "invalid qos"
        topic = io.read_string
        remaining_length -= (2 + topic.bytesize)
        if qos.positive?
          packet_id = io.read_int
          remaining_length -= 2
        end
        payload = io.read_bytes(remaining_length.to_u16)
        self.new(topic, payload, packet_id, dup, qos, retain)
      end

      def to_io(io)
        remaining_length = 0
        flags = 0u8
        flags |= 0b0000_1000u8 if dup?
        flags |= 0b0000_0001u8 if retain?
        flags |= (0b0000_0110u8 & (qos << 1)) if qos.positive?
        io.write_byte ((TYPE << 4) | flags)
        remaining_length += (2 + topic.bytesize) + body.bytesize
        if qos.positive?
          remaining_length += 2 # packet_id
        end
        io.write_remaining_length remaining_length
        io.write_string topic
        io.write_int packet_id.not_nil! if qos.positive?
        io.write_bytes_raw(body)
      end
    end

    struct Unsubscribe < Packet
      TYPE = 10u8
      getter packet_id, topics

      def initialize(@topics : Array(String), @packet_id : UInt16)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags == 2, "invalid flags"
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

      private def remaining_length
        # This is the length of variable header (2 bytes) plus the length of the payload.
        length = 2
        @topics.each do |topic|
          length += (2 + topic.bytesize)
        end
        length
      end
    end

    struct UnsubAck < Packet
      TYPE = 11u8

      getter packet_id

      def initialize(@packet_id : UInt16)
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags.zero?, "invalid flags"
        decode_assert remaining_length == 2, "invalid length"
        packet_id = io.read_int
        self.new(packet_id)
      end

      def to_io(io)
        io.write_byte (TYPE << 4)
        io.write_remaining_length 2
        io.write_int(packet_id)
      end
    end

    abstract struct SimplePacket < Packet
      private abstract def type

      def self.from_io(io : MQTT::Protocol::IO, flags : UInt8, remaining_length : UInt32)
        decode_assert flags.zero?, "invalid flags"
        decode_assert remaining_length.zero?, "invalid length"
        self.new
      end

      def to_io(io)
        io.write_byte(type << 4)
        io.write_remaining_length 0
      end

      def initialize
      end
    end

    struct PingReq < SimplePacket
      TYPE = 12u8

      private def type
        TYPE
      end
    end

    struct PingResp < SimplePacket
      TYPE = 13u8

      private def type
        TYPE
      end
    end

    struct Disconnect < SimplePacket
      TYPE = 14u8

      private def type
        TYPE
      end
    end
  end
end
