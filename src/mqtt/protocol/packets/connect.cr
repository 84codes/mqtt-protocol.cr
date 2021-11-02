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

      getter client_id, keepalive, username, password, will
      getter? clean_session

      def initialize(@client_id, @clean_session, @keepalive, @username, @password, @will)
        # Remaining length is at least 10:
        # protocol name (str) + protocol version (byte) + connect flags (byte) + keep alive (int)
        @remaining_length = 10

        # ClientID
        @remaining_length += sizeof(UInt16)
        @remaining_length += client_id.bytesize

        if w = will
          @remaining_length += w.bytesize
        end
        if u = username
          @remaining_length += sizeof(UInt16)
          @remaining_length += u.bytesize
          if pwd = password
            @remaining_length += sizeof(UInt16)
            @remaining_length += pwd.bytesize
          end
        end
      end

      def self.from_io(io : MQTT::Protocol::IO, flags : Flags, _remaining_length)
        decode_assert flags.zero?, MQTT::Protocol::Error::InvalidFlags, flags

        protocol_len = io.read_int
        decode_assert protocol_len == 4, "invalid protocol length: #{protocol_len}"

        protocol = io.read_string(protocol_len)
        decode_assert protocol == "MQTT", "invalid protocol: #{protocol.inspect}"

        version = io.read_byte
        decode_assert version == 0x04, Error::UnacceptableProtocolVersion

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

        client_id_len = io.read_int
        decode_assert client_id_len < 256, "client id too long: #{client_id_len} > 255"
        client_id = io.read_string(client_id_len)

        if client_id.to_s.empty?
          decode_assert clean_session == true, Error::IdentifierRejected
        end

        will = has_will ? Will.from_io(io, will_qos, will_retain) : nil
        username = io.read_string if has_username
        password = io.read_bytes if has_password

        self.new(client_id, clean_session, keepalive, username, password, will)
      end

      # ameba:disable Metrics/CyclomaticComplexity
      def to_io(io)
        # Remaining length is at least 10:
        # protocol name (str) + protocol version (byte) + connect flags (byte) + keep alive (int)
        connect_flags = 0u8
        if w = will
          connect_flags |= 0b0000_0100u8
          connect_flags |= 0b0010_0000u8 if w.retain?
          connect_flags |= ((w.qos & 0b0000_0011u8) << 3)
        end
        if u = username
          connect_flags |= 0b1000_0000u8
          if pwd = password
            connect_flags |= 0b0100_0000u8
          end
        end
        connect_flags |= 0b0000_0010u8 if clean_session?
        io.write_byte (TYPE << 4)
        io.write_remaining_length remaining_length
        io.write_string "MQTT"
        io.write_byte 4u8 # "protocol version"
        io.write_byte connect_flags
        io.write_int keepalive
        io.write_string client_id if client_id
        w.to_io(io) if w
        io.write_string u if u
        io.write_bytes pwd if pwd
      end
    end

    struct Will
      getter topic, payload, qos
      getter? retain

      def initialize(@topic : String, @payload : Bytes, @qos : UInt8, @retain : Bool)
        raise ArgumentError.new("Topic cannot contain wildcard") if @topic.matches?(/[#+]/)
      end

      def self.from_io(io : MQTT::Protocol::IO, qos : UInt8, retain : Bool)
        topic = io.read_string
        payload = io.read_bytes
        self.new(topic, payload, qos, retain)
      rescue ex : ArgumentError
        raise MQTT::Protocol::Error::PacketDecode.new(ex.message)
      end

      def to_io(io)
        io.write_string topic
        io.write_bytes payload
      end

      def bytesize
        bytesize = 0
        bytesize += sizeof(UInt16)
        bytesize += topic.bytesize
        bytesize += sizeof(UInt16)
        bytesize += payload.bytesize
        bytesize
      end
    end
  end
end
