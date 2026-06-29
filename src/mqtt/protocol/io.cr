require "./packets"

module MQTT
  MAX_PAYLOAD_SIZE = 268_435_455u32 # 256MiB
  MAX_MULTIPLIER   = (128 * 128 * 128).to_u32

  module Protocol
    # Byte transport for MQTT packets. The version-independent wire primitives
    # (integers, strings, Variable Byte Integers, ...) live here; the framing
    # that *differs* between protocol versions - whether a properties section or
    # a reason-code byte is present - lives on the `IO::V3` / `IO::V5`
    # subclasses so packet codecs stay version-agnostic.
    #
    # The version is fixed by the concrete type at construction (no mutable
    # field, no default): you decode/encode through an `IO::V3` or an `IO::V5`,
    # so a v5 packet can never be silently parsed with v3 framing. The one
    # exception is the initial CONNECT, which carries the version on the wire -
    # see `.read_connect`.
    abstract class IO
      getter io

      # The protocol version this IO frames for. Derived from the concrete type,
      # so it is immutable for the lifetime of the connection.
      abstract def version : Version

      @max_packet_size : UInt32

      def initialize(@io : ::IO, max_packet_size : UInt32? = nil,
                     @byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian)
        @max_packet_size = max_packet_size || MAX_PAYLOAD_SIZE
      end

      # Build the IO that frames for `version` over the same transport.
      def self.for(version : Version, io : ::IO, max_packet_size : UInt32? = nil,
                   byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian) : IO
        if version.v5?
          V5.new(io, max_packet_size, byte_format)
        else
          V3.new(io, max_packet_size, byte_format)
        end
      end

      # Read the opening CONNECT off a fresh connection, detecting the protocol
      # version it negotiates, and return it together with the versioned IO to
      # use for every subsequent packet. This is the one place the version is
      # discovered from the wire rather than chosen up front.
      def self.read_connect(io : ::IO, max_packet_size : UInt32? = nil,
                            byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian) : {Connect, IO}
        # CONNECT's header up to the protocol-level byte is version-independent,
        # and Connect.from_io reframes itself once the level is known, so any
        # concrete IO can bootstrap the read.
        boot = V3.new(io, max_packet_size, byte_format)
        connect = boot.read_packet.as(Connect)
        {connect, for(connect.version, io, max_packet_size, byte_format)}
      end

      # Return an IO framing for `version` over the same transport, or self if it
      # already matches. Used by CONNECT, which establishes the version mid-read.
      def reframe(version : Version) : IO
        return self if version == self.version
        IO.for(version, @io, @max_packet_size, @byte_format)
      end

      forward_missing_to @io

      def read_packet : Packet
        Packet.from_io(self)
      end

      def write(packet : Packet)
        write_packet(packet)
      end

      def write_packet(packet : Packet)
        packet.to_io(self)
      end

      # Underlying read that returns nil at a clean end-of-stream (vs raising),
      # so the packet dispatcher can tell "connection closed" from "truncated
      # packet".
      def read_byte? : UInt8?
        @io.read_byte
      end

      def read_byte
        @io.read_byte || raise ::IO::EOFError.new
      end

      def read_string(len : UInt16? = nil)
        len = read_int unless len
        raise Error::PacketTooLarge.new(@max_packet_size, len) if len > @max_packet_size
        str = @io.read_string(len)
        if str.includes?('\u0000') || !str.valid_encoding?
          raise MQTT::Protocol::Error::PacketDecode.new "Illformed UTF-8 string"
        end
        str
      end

      def read_int
        UInt16.from_io(@io, @byte_format)
      end

      def read_four_byte_int : UInt32
        UInt32.from_io(@io, @byte_format)
      end

      def read_string_pair : {String, String}
        {read_string, read_string}
      end

      # Variable Byte Integer (MQTT-1.5.5): up to four bytes, seven value bits
      # each with the MSB as a continuation flag. The encoding MUST be minimal
      # (MQTT-1.5.5-1), so a non-minimal encoding is rejected as malformed -
      # otherwise an overlong value desyncs the property consumed-counter.
      def read_variable_byte_int : UInt32
        multiplier : UInt32 = 1
        value : UInt32 = 0
        bytes_read = 0
        loop do
          b = @io.read_byte || raise ::IO::EOFError.new
          bytes_read += 1
          value += (b.to_u32 & 127u32) * multiplier
          break if b & 128 == 0
          multiplier *= 128
          raise Error::PacketDecode.new "invalid variable byte integer" if multiplier > MAX_MULTIPLIER
        end
        if bytes_read != IO.variable_byte_int_size(value)
          raise Error::PacketDecode.new "non-minimal variable byte integer"
        end
        value
      end

      def read_remaining_length : UInt32
        value = read_variable_byte_int
        raise Error::PacketTooLarge.new(@max_packet_size, value) if value > @max_packet_size
        value
      end

      def read_bytes(len : Int? = nil)
        len = read_int unless len
        raise Error::PacketTooLarge.new(@max_packet_size, len) if len > @max_packet_size
        bytes = Bytes.new(len)
        @io.read_fully(bytes)
        bytes
      end

      # Subtract `n` bytes from the bytes left to read in the current packet,
      # raising a clean PacketDecode (rather than an OverflowError) when a peer
      # declares a section larger than what remains.
      def consume(remaining : UInt32, n : Int) : UInt32
        if n > remaining
          raise Error::PacketDecode.new "section of #{n} bytes exceeds #{remaining} remaining"
        end
        remaining - n.to_u32
      end

      # --- version-dependent framing hooks -----------------------------------
      #
      # Every difference between v3 and v5 wire framing lives here as a pair of
      # IO::V3 / IO::V5 implementations, so packet codecs call a hook and never
      # branch on the version themselves. The generic hooks (returning a parsed
      # properties/reason type) need a concrete base method because Crystal can't
      # express an abstract def with a free return type; both subclasses still
      # override it, so the base body is never reached.

      # Parse a properties section, returning it with the wire bytes it consumed
      # (0 on v3, where there is no section), so callers advance their
      # remaining-length counter without knowing the version. `remaining` is the
      # bytes left in the enclosing packet at this point: the section's declared
      # length is bounded by it, so a peer cannot drive a read past the packet.
      def read_properties(klass : T.class, remaining : UInt32) : {T, UInt32} forall T
        raise NotImplementedError.new("read_properties")
      end

      # The PUBACK/PUBREC/PUBREL/PUBCOMP tail after the packet id. Returns the
      # raw reason byte (nil when omitted) and the parsed properties. The v3
      # impl asserts the bare-packet-id length, making the dropped-gate bug (a v3
      # PUBREL/PUBCOMP misparsed as v5) structurally impossible.
      def read_ack_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
        raise NotImplementedError.new("read_ack_tail")
      end

      # The optional reason byte + properties tail of DISCONNECT / AUTH. Same
      # shape as the ack tail but with no packet id (so v3 expects an empty body).
      def read_reason_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
        raise NotImplementedError.new("read_reason_tail")
      end

      abstract def write_properties(properties) : Nil
      abstract def write_ack(first_byte : UInt8, packet_id : UInt16, reason_value : UInt8, properties) : Nil
      abstract def write_reason_tail(first_byte : UInt8, reason_value : UInt8, properties) : Nil
      # Validate a SUBSCRIBE option byte's version-reserved bits ([MQTT-3.8.3-5]).
      abstract def validate_subscription_options(options : UInt8) : Nil
      # Interpret a CONNACK code byte: a v3 return code or a v5 reason code.
      abstract def read_connack_reason(byte : UInt8)
      # Write the CONNACK body after the fixed header + remaining length.
      abstract def write_connack_body(session_present : Bool, reason, properties) : Nil
      # Whether an empty PUBLISH topic is legal (v5, resolved via a Topic Alias).
      abstract def allow_empty_topic? : Bool

      def write_byte(b : UInt8)
        @io.write_byte b
      end

      def write_bytes(bytes : Bytes)
        write_int bytes.bytesize
        @io.write bytes
      end

      def write_bytes_raw(bytes : Bytes)
        @io.write bytes
      end

      def write_bytes(bytes : Nil)
        write_int 0
      end

      def write_string(str : String)
        write_int str.bytesize
        @io.write str.to_slice
      end

      def write_string(str : Nil)
        write_int 0
      end

      def write_int(int : Int)
        @io.write_bytes int.to_u16, @byte_format
      end

      def write_four_byte_int(int : UInt32)
        @io.write_bytes int, @byte_format
      end

      def write_string_pair(key : String, value : String)
        write_string key
        write_string value
      end

      # Variable Byte Integer (MQTT-1.5.5).
      def write_variable_byte_int(value : Int)
        if value < 0 || value > MAX_PAYLOAD_SIZE
          raise Error::PacketEncode.new "variable byte integer out of range: #{value}"
        end
        loop do
          b = (value % 128).to_u8
          value //= 128
          b |= 128u8 if value > 0
          @io.write_byte b
          break if value <= 0
        end
      end

      def write_remaining_length(length)
        write_variable_byte_int(length)
      end

      # Number of bytes a Variable Byte Integer of this value occupies on the
      # wire. The inverse of the byte-count thresholds, used to precompute a
      # packet's remaining_length without serialising it first.
      def self.variable_byte_int_size(value : Int) : Int32
        if value < 128
          1
        elsif value < 16_384
          2
        elsif value < 2_097_152
          3
        else
          4
        end
      end

      # MQTT 3.1 / 3.1.1 framing: no properties sections, no reason codes; the
      # ack/disconnect bodies are degenerate (bare packet id / empty).
      class V3 < IO
        def version : Version
          Version::V3_1_1
        end

        def read_properties(klass : T.class, remaining : UInt32) : {T, UInt32} forall T
          {klass.new, 0u32}
        end

        def write_properties(properties) : Nil
        end

        def read_ack_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
          unless remaining_length == 2
            raise Error::PacketDecode.new "invalid length #{remaining_length} for v3 ack"
          end
          {nil, properties_klass.new}
        end

        def write_ack(first_byte : UInt8, packet_id : UInt16, reason_value : UInt8, properties) : Nil
          write_byte(first_byte)
          write_remaining_length(2)
          write_int(packet_id)
        end

        def read_reason_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
          unless remaining_length.zero?
            raise Error::PacketDecode.new "invalid length #{remaining_length} for v3"
          end
          {nil, properties_klass.new}
        end

        def write_reason_tail(first_byte : UInt8, reason_value : UInt8, properties) : Nil
          write_byte(first_byte)
          write_remaining_length(0)
        end

        def validate_subscription_options(options : UInt8) : Nil
        end

        def read_connack_reason(byte : UInt8)
          unless byte < 6
            raise Error::PacketDecode.new "invalid return code: #{byte}"
          end
          Connack::ReasonCode.from_v3_return_code(Connack::ReturnCode.new(byte))
        end

        def write_connack_body(session_present : Bool, reason, properties) : Nil
          write_byte(session_present ? 1u8 : 0u8)
          return_code = reason.to_v3_return_code ||
                        raise Error::PacketEncode.new("no v3 return code for #{reason}")
          write_byte(return_code.value)
        end

        def allow_empty_topic? : Bool
          false
        end
      end

      # MQTT 5.0 framing: properties sections and reason codes throughout.
      class V5 < IO
        def version : Version
          Version::V5
        end

        def read_properties(klass : T.class, remaining : UInt32) : {T, UInt32} forall T
          props = klass.from_io(self, remaining)
          {props, props.bytesize.to_u32}
        end

        def write_properties(properties) : Nil
          properties.to_io(self)
        end

        # Omission rules 3.4.2.1: reason 0x00 + no properties => bare packet id
        # (remaining length 2); reason set but no properties => length 3.
        def read_ack_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
          return {nil, properties_klass.new} if remaining_length <= 2
          reason = read_byte
          return {reason, properties_klass.new} if remaining_length == 3
          avail = remaining_length - 3
          props = properties_klass.from_io(self, avail)
          unless props.bytesize.to_u32 == avail
            raise Error::ProtocolError.new(0x81u8, "ack properties length mismatch")
          end
          {reason, props}
        end

        def write_ack(first_byte : UInt8, packet_id : UInt16, reason_value : UInt8, properties) : Nil
          write_byte(first_byte)
          if reason_value.zero? && properties.empty?
            write_remaining_length(2)
            write_int(packet_id)
          elsif properties.empty?
            write_remaining_length(3)
            write_int(packet_id)
            write_byte(reason_value)
          else
            write_remaining_length(3 + properties.bytesize)
            write_int(packet_id)
            write_byte(reason_value)
            properties.to_io(self)
          end
        end

        # As the ack tail but with no packet id: empty body => default reason +
        # no properties; one byte => bare reason; more => reason + properties.
        def read_reason_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
          return {nil, properties_klass.new} if remaining_length.zero?
          reason = read_byte
          return {reason, properties_klass.new} if remaining_length == 1
          avail = remaining_length - 1
          props = properties_klass.from_io(self, avail)
          unless props.bytesize.to_u32 == avail
            raise Error::ProtocolError.new(0x81u8, "reason tail properties length mismatch")
          end
          {reason, props}
        end

        def write_reason_tail(first_byte : UInt8, reason_value : UInt8, properties) : Nil
          write_byte(first_byte)
          if reason_value.zero? && properties.empty?
            write_remaining_length(0)
          elsif properties.empty?
            write_remaining_length(1)
            write_byte(reason_value)
          else
            write_remaining_length(1 + properties.bytesize)
            write_byte(reason_value)
            properties.to_io(self)
          end
        end

        def validate_subscription_options(options : UInt8) : Nil
          if (options & 0b1100_0000u8) != 0
            raise Error::ProtocolError.new(0x81u8, "reserved subscription option bits set")
          end
        end

        def read_connack_reason(byte : UInt8)
          Connack::ReasonCode.from_value?(byte) ||
            raise Error::ProtocolError.new(0x81u8, "invalid connack reason code #{byte}")
        end

        def write_connack_body(session_present : Bool, reason, properties) : Nil
          write_byte(session_present ? 1u8 : 0u8)
          write_byte(reason.value)
          properties.to_io(self)
        end

        def allow_empty_topic? : Bool
          true
        end
      end
    end
  end
end
