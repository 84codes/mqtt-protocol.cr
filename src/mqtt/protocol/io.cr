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

      # Bytes left to read in the current inbound packet, `nil` outside a
      # packet read. A mutable box (not a plain ivar) so a CONNECT `reframe`
      # mid-packet hands the same budget to the new IO and the dispatcher's
      # final check sees every byte the reframed IO consumed.
      class Budget
        property remaining : UInt32? = nil
      end

      @max_packet_size : UInt32
      @budget : Budget

      def initialize(@io : ::IO, max_packet_size : UInt32? = nil,
                     @byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian,
                     budget : Budget? = nil)
        @max_packet_size = max_packet_size || MAX_PAYLOAD_SIZE
        @budget = budget || Budget.new
      end

      # Build the IO that frames for `version` over the same transport.
      def self.for(version : Version, io : ::IO, max_packet_size : UInt32? = nil,
                   byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian,
                   budget : Budget? = nil) : IO
        if version.v5?
          V5.new(io, max_packet_size, byte_format, budget)
        else
          V3.new(io, max_packet_size, byte_format, budget)
        end
      end

      # Read the opening CONNECT off a fresh connection and return it with a
      # versioned IO for every subsequent packet. Convenience wrapper: a server
      # that rejects a bad CONNECT should use the instance `#read_connect`, which
      # keeps an IO to frame the rejection CONNACK on.
      def self.read_connect(io : ::IO, max_packet_size : UInt32? = nil,
                            byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian) : {Connect, IO}
        V3.new(io, max_packet_size, byte_format).read_connect
      end

      # Read the opening CONNECT on this bootstrap IO (a v3 IO; CONNECT reveals
      # the version on the wire) and return it with the IO reframed to that
      # version. The tuple only rebinds on success, so the caller's boot IO
      # survives a parse error, letting a rejecting server answer with a CONNACK:
      #
      #     io = MQTT::Protocol::IO::V3.new(socket, max)
      #     connect, io = io.read_connect
      #     # rescue Error::Connect -> io is still the boot IO, can send CONNACK
      def read_connect : {Connect, IO}
        # [MQTT-3.1.0-1]: the first packet MUST be a CONNECT.
        connect = read_packet.as?(Connect) ||
                  raise Error::PacketDecode.new("first packet must be CONNECT")
        {connect, reframe(connect.version)}
      end

      # Return an IO framing for `version` over the same transport, or self if it
      # already matches. Used by CONNECT, which establishes the version mid-read;
      # the packet byte budget is shared so the switch happens mid-packet.
      def reframe(version : Version) : IO
        return self if version == self.version
        IO.for(version, @io, @max_packet_size, @byte_format, @budget)
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

      # Wire size of `packet` when framed for this IO's version. The IO is the
      # single source of truth for the version, so callers can't measure a
      # packet with a different version than `write_packet` would use.
      def bytesize(packet : Packet) : UInt32
        packet.bytesize(version)
      end

      # --- packet byte budget ------------------------------------------------
      #
      # `Packet.read_body` starts the budget with the packet's remaining length;
      # every read primitive then charges the bytes it is about to read, so no
      # parse - present or future - can read past the packet boundary
      # ([MQTT-2.1.4]-style framing integrity, enforced structurally instead of
      # per codec). These three are for the dispatcher; codecs never call them.

      def start_packet(remaining_length : UInt32) : Nil
        @budget.remaining = remaining_length
      end

      # Reject a packet whose codec consumed fewer bytes than the declared
      # remaining length: the leftovers would desync the next packet's header.
      def finish_packet : Nil
        if (remaining = @budget.remaining) && remaining > 0
          raise Error::ProtocolError.new(0x81u8, "packet has #{remaining} trailing bytes")
        end
      end

      # Deactivate the budget, also on error paths, so a stale budget never
      # charges the next packet's header.
      def abort_packet : Nil
        @budget.remaining = nil
      end

      # Bytes left to read in the current packet (0 outside a packet read).
      def remaining_in_packet : UInt32
        @budget.remaining || 0u32
      end

      # Charge `n` bytes against the current packet's budget BEFORE reading
      # them, raising Malformed Packet (0x81) when the packet has fewer bytes
      # left - on a streaming socket an unbounded read would otherwise block
      # waiting for bytes that belong to a later packet (or never arrive).
      # Inactive (nil budget) outside a packet read.
      private def charge(n : Int) : Nil
        if remaining = @budget.remaining
          if n > remaining
            raise Error::ProtocolError.new(0x81u8, "field of #{n} bytes exceeds #{remaining} bytes left in packet")
          end
          @budget.remaining = remaining - n.to_u32
        end
      end

      # Underlying read that returns nil at a clean end-of-stream (vs raising),
      # so the packet dispatcher can tell "connection closed" from "truncated
      # packet". Uncharged: only used for the fixed header's first byte, before
      # a packet is committed.
      def read_byte? : UInt8?
        @io.read_byte
      end

      def read_byte
        charge(1)
        @io.read_byte || raise ::IO::EOFError.new
      end

      def read_string(len : UInt16? = nil)
        len = read_int if len.nil?
        raise Error::PacketTooLarge.new(@max_packet_size, len) if len > @max_packet_size
        charge(len)
        str = @io.read_string(len)
        if str.includes?('\u0000') || !str.valid_encoding?
          raise MQTT::Protocol::Error::PacketDecode.new "Illformed UTF-8 string"
        end
        str
      end

      def read_int
        charge(2)
        UInt16.from_io(@io, @byte_format)
      end

      def read_four_byte_int : UInt32
        charge(4)
        UInt32.from_io(@io, @byte_format)
      end

      def read_string_pair : {String, String}
        key = read_string
        value = read_string
        {key, value}
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
          charge(1)
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
        len = read_int if len.nil?
        raise Error::PacketTooLarge.new(@max_packet_size, len) if len > @max_packet_size
        charge(len)
        bytes = Bytes.new(len)
        @io.read_fully(bytes)
        bytes
      end

      # --- version-dependent framing hooks -----------------------------------
      #
      # Every difference between v3 and v5 wire framing lives here as a pair of
      # IO::V3 / IO::V5 implementations, so packet codecs call a hook and never
      # branch on the version themselves. The generic hooks (returning a parsed
      # properties/reason type) need a concrete base method because Crystal can't
      # express an abstract def with a free return type; both subclasses still
      # override it, so the base body is never reached.

      # Parse a properties section (an empty one on v3, where there is no
      # section on the wire). Bounds come from the packet byte budget, so a
      # peer cannot drive a read past the packet.
      def read_properties(klass : T.class) : T forall T
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
      # Reject packet types that do not exist in this version, before any body
      # bytes are read. Keeps the version-blind dispatcher from parsing
      # v5-only packets on a v3 connection.
      abstract def validate_packet_type(type : UInt8) : Nil
      # Interpret a CONNACK code byte: a v3 return code or a v5 reason code.
      abstract def read_connack_reason(byte : UInt8)
      # Interpret a SUBACK payload byte: v3 allows only the granted-QoS values
      # and 0x80 (Failure); v5 has the full reason-code set.
      abstract def read_suback_reason(byte : UInt8) : SubAck::ReasonCode
      # Write the CONNACK body after the fixed header + remaining length.
      abstract def write_connack_body(session_present : Bool, reason, properties) : Nil
      # Whether an empty PUBLISH topic is legal (v5, resolved via a Topic Alias).
      abstract def allow_empty_topic? : Bool
      # Whether UNSUBACK carries a body beyond the packet id (v5: properties +
      # per-topic reason codes; v3: a bare packet id).
      abstract def unsuback_payload? : Bool

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

      # Wire size of a v5 reason-code + properties tail, encoding the omission
      # rule of 3.4.2.1 / 3.14.2.2 / 3.15.2.2: a zero (success/normal) reason
      # with no properties is omitted entirely, and the properties section is
      # omitted when empty and the reason is the last byte. The single source
      # of truth for this rule - both the remaining_length arithmetic and the
      # V5 writers derive from it, so the reported size can't drift from what
      # is written.
      def self.tail_bytesize(reason_value : UInt8, properties) : UInt32
        if reason_value.zero? && properties.empty?
          0u32
        elsif properties.empty?
          1u32
        else
          (1 + properties.bytesize).to_u32
        end
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

        def read_properties(klass : T.class) : T forall T
          klass.new
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
          # MQTT 3.1.1: only the two QoS bits are defined; bits 7-2 are reserved
          # and MUST be zero, otherwise the packet is malformed [MQTT-3-8.3-4].
          # (v5 gives bits 2-5 meaning, so this rejection is v3-only.)
          unless (options & 0b1111_1100u8).zero?
            raise Error::PacketDecode.new "Malformed packet: reserved subscription option bits set"
          end
        end

        def validate_packet_type(type : UInt8) : Nil
          # Type 15 (AUTH) is reserved in v3 and MUST be treated as a
          # protocol violation [MQTT-2.2.1].
          if type == Auth::TYPE
            raise Error::PacketDecode.new "invalid packet type #{type}"
          end
        end

        def read_connack_reason(byte : UInt8)
          unless byte < 6
            raise Error::PacketDecode.new "invalid return code: #{byte}"
          end
          Connack::ReasonCode.from_v3_return_code(Connack::ReturnCode.new(byte))
        end

        def read_suback_reason(byte : UInt8) : SubAck::ReasonCode
          # v3.1.1 SUBACK return codes are 0-2 (granted QoS) or 0x80 Failure
          # [MQTT-3.9.3-2]; 0x80 maps onto the v5 UnspecifiedError member.
          unless byte <= 2 || byte == 0x80
            raise Error::PacketDecode.new "invalid suback return code #{byte}"
          end
          SubAck::ReasonCode.new(byte)
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

        def unsuback_payload? : Bool
          false
        end
      end

      # MQTT 5.0 framing: properties sections and reason codes throughout.
      class V5 < IO
        def version : Version
          Version::V5
        end

        def read_properties(klass : T.class) : T forall T
          klass.from_io(self, remaining_in_packet)
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
          # The section must consume the rest of the packet exactly: an overrun
          # is caught by the byte budget, leftovers by the dispatcher's
          # finish_packet.
          {reason, properties_klass.from_io(self, remaining_in_packet)}
        end

        def write_ack(first_byte : UInt8, packet_id : UInt16, reason_value : UInt8, properties) : Nil
          write_byte(first_byte)
          tail = IO.tail_bytesize(reason_value, properties)
          write_remaining_length(2 + tail)
          write_int(packet_id)
          write_byte(reason_value) unless tail.zero?
          properties.to_io(self) if tail > 1
        end

        # As the ack tail but with no packet id: empty body => default reason +
        # no properties; one byte => bare reason; more => reason + properties.
        def read_reason_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
          return {nil, properties_klass.new} if remaining_length.zero?
          reason = read_byte
          return {reason, properties_klass.new} if remaining_length == 1
          # Exact consumption enforced by the byte budget + finish_packet.
          {reason, properties_klass.from_io(self, remaining_in_packet)}
        end

        def write_reason_tail(first_byte : UInt8, reason_value : UInt8, properties) : Nil
          write_byte(first_byte)
          tail = IO.tail_bytesize(reason_value, properties)
          write_remaining_length(tail)
          write_byte(reason_value) unless tail.zero?
          properties.to_io(self) if tail > 1
        end

        def validate_subscription_options(options : UInt8) : Nil
          if (options & 0b1100_0000u8) != 0
            raise Error::ProtocolError.new(0x81u8, "reserved subscription option bits set")
          end
        end

        def validate_packet_type(type : UInt8) : Nil
        end

        def read_connack_reason(byte : UInt8)
          Connack::ReasonCode.from_value?(byte) ||
            raise Error::ProtocolError.new(0x81u8, "invalid connack reason code #{byte}")
        end

        def read_suback_reason(byte : UInt8) : SubAck::ReasonCode
          SubAck::ReasonCode.from_value?(byte) ||
            raise Error::ProtocolError.new(0x81u8, "invalid suback reason code #{byte}")
        end

        def write_connack_body(session_present : Bool, reason, properties) : Nil
          write_byte(session_present ? 1u8 : 0u8)
          write_byte(reason.value)
          properties.to_io(self)
        end

        def allow_empty_topic? : Bool
          true
        end

        def unsuback_payload? : Bool
          true
        end
      end
    end
  end
end
