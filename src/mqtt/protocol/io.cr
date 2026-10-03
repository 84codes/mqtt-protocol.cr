require "./packets"

module MQTT
  MAX_PAYLOAD_SIZE = 268_435_455u32 # 256MiB
  MAX_MULTIPLIER   = (128 * 128 * 128).to_u32

  module Protocol
    # Byte transport for MQTT packets. The version-independent wire primitives
    # (integers, strings, Variable Byte Integers, ...) live here; the framing
    # that *differs* between protocol versions - whether a properties section or
    # a reason-code byte is present - lives on a `Framing` strategy the IO holds,
    # so packet codecs stay version-agnostic.
    #
    # One IO per connection, with a stable identity for its whole life. The
    # version is write-once: either pinned at construction (a client knows what
    # it speaks before it dials) or discovered from the wire, since CONNECT is
    # the only packet that announces it. A server therefore does not need to
    # know the version up front:
    #
    #     io = MQTT::Protocol::IO.new(socket, max_packet_size)
    #     connect = io.read_connect   # io now frames for connect.version
    #
    # Until CONNECT reveals the version the IO sits in `Framing::Bootstrap`,
    # which reads only CONNECT and writes only CONNECT or a v3-framed CONNACK -
    # the right framing for rejecting a client whose version we never learned
    # ([MQTT-3.1.2-2]). Because the IO switches framing in place, a CONNECT that
    # fails *after* the protocol level byte is answered with a CONNACK framed
    # for the version the client actually asked for.
    class IO
      getter io

      # Wire sizes of the fixed-width fields the framing arithmetic is built
      # from. Named (and derived from the type actually read or written) so a
      # byte-budget charge or a remaining_length calculation cannot silently
      # disagree with the bytes that hit the wire.
      PACKET_ID_BYTESIZE   = sizeof(UInt16).to_u32 # §2.2.1
      REASON_CODE_BYTESIZE = sizeof(UInt8).to_u32

      # Bytes left to read in the current inbound packet, and the rules that
      # keep that count honest.
      #
      # `Packet.read_body` starts the budget with the packet's remaining
      # length; every read primitive then charges the bytes it is about to
      # read, so no parse - present or future - can read past the packet
      # boundary (section 2.1.4 framing integrity, enforced structurally
      # instead of per codec). The count is private: the whole state machine
      # lives here, so no caller can desync it by assigning to it.
      class Budget
        # `nil` outside a packet read - an inactive budget charges nothing, so
        # the fixed header can be read before a packet is committed.
        @remaining : UInt32? = nil

        # Bytes left to read in the current packet (0 outside a packet read).
        # Inactive and fully-consumed both report 0: callers only ever ask
        # "how much may I still read?", and the answer is the same for both.
        def remaining : UInt32
          @remaining || 0u32
        end

        def start(remaining_length : UInt32) : Nil
          @remaining = remaining_length
        end

        # Arm from an explicit bound when no packet read is in progress. A
        # no-op mid-packet, so the dispatcher path is unaffected; see
        # `IO#ensure_packet_budget` for why the entry points need this.
        def ensure_started(remaining_length : UInt32) : Nil
          start(remaining_length) if remaining.zero?
        end

        # Charge `n` bytes against the current packet's budget BEFORE reading
        # them, raising Malformed Packet (0x81) when the packet has fewer
        # bytes left - on a streaming socket an unbounded read would otherwise
        # block waiting for bytes that belong to a later packet (or never
        # arrive). Inactive (nil budget) outside a packet read.
        def charge(n : Int) : Nil
          return unless rem = @remaining
          if n > rem
            raise Error::ProtocolError.new(0x81u8, "field of #{n} bytes exceeds #{rem} bytes left in packet")
          end
          @remaining = rem - n.to_u32
        end

        # Reject a packet whose codec consumed fewer bytes than the declared
        # remaining length: the leftovers would desync the next packet's header.
        def finish : Nil
          if (rem = @remaining) && rem > 0
            raise Error::ProtocolError.new(0x81u8, "packet has #{rem} trailing bytes")
          end
        end

        # Deactivate the budget, also on error paths, so a stale budget never
        # charges the next packet's header.
        def deactivate : Nil
          @remaining = nil
        end
      end

      @max_packet_size : UInt32
      @budget : Budget
      @framing : Framing::Base

      # `version` pins the framing up front (a client knows what it speaks);
      # leaving it `Unknown` starts the IO in `Framing::Bootstrap`, where
      # `#read_connect` discovers the version from the wire.
      def initialize(@io : ::IO, max_packet_size : UInt32? = nil,
                     @byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian,
                     version : Version = Version::Unknown)
        @max_packet_size = max_packet_size || MAX_PAYLOAD_SIZE
        @budget = Budget.new
        @framing = Framing.for(version)
      end

      # Build an IO pinned to `version` over `io` (`Unknown` pins nothing, as `.new`).
      def self.for(version : Version, io : ::IO, max_packet_size : UInt32? = nil,
                   byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian) : IO
        new(io, max_packet_size, byte_format, version)
      end

      # Pinned-version conveniences. `v3` defaults to 3.1.1; pass `Version::V3_1`
      # for an MQIsdp connection so `#version` stays honest.
      def self.v3(io : ::IO, max_packet_size : UInt32? = nil,
                  byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian,
                  version : Version = Version::V3_1_1) : IO
        raise ArgumentError.new("#{version} is not a v3 version") unless version.v3_1? || version.v3_1_1?
        new(io, max_packet_size, byte_format, version)
      end

      def self.v5(io : ::IO, max_packet_size : UInt32? = nil,
                  byte_format : ::IO::ByteFormat = ::IO::ByteFormat::NetworkEndian) : IO
        new(io, max_packet_size, byte_format, Version::V5)
      end

      # The protocol version this IO frames for, `Unknown` until pinned or read
      # off a CONNECT. Every sizing rule branches on `v5?`, so `Unknown` sizes
      # as v3 - the framing `Bootstrap` writes a rejection CONNACK with.
      def version : Version
        @framing.version
      end

      # Whether the version has been established - pinned at construction or
      # read off a CONNECT.
      def negotiated? : Bool
        !version.unknown?
      end

      # Switch framing to `version`, in place. Called by the CONNECT codec the
      # moment the protocol level byte is read, so the rest of that packet - and
      # every later packet, and any CONNACK rejecting this very CONNECT - is
      # framed for the version the peer asked for.
      #
      # Write-once: an IO already negotiated - pinned at construction or by an
      # earlier CONNECT - keeps its version, so a second CONNECT cannot reframe
      # a live connection ([MQTT-3.1.0-2]). Returns false on a mismatch and
      # leaves the caller to raise the error for its direction.
      protected def negotiate(version : Version) : Bool
        return @framing.version == version if negotiated?
        @framing = Framing.for(version)
        true
      end

      # Read the opening CONNECT and leave this IO framing for its version.
      # [MQTT-3.1.0-1]: the first packet MUST be a CONNECT - a bootstrap IO
      # rejects every other type before reading its body.
      #
      # The IO keeps its identity, so a server that rejects the CONNECT answers
      # on the same object, with the framing the CONNECT got as far as revealing:
      #
      #     io = MQTT::Protocol::IO.new(socket, max)
      #     connect = io.read_connect
      #     # rescue Error::Connect -> io still usable, and a CONNACK is framed
      #     # for whatever version the CONNECT announced before it failed
      def read_connect : Connect
        read_packet.as?(Connect) ||
          raise Error::PacketDecode.new("first packet must be CONNECT")
      end

      # Deliberately NO forward_missing_to: an unwrapped ::IO read (read_fully,
      # skip, gets, ...) would bypass the packet byte budget and falsify its
      # guarantee. Only the transport lifecycle ops below - which never touch
      # the budget - are delegated explicitly; a socket-specific method like
      # `write_timeout=` still needs the public `io` getter, consciously.
      delegate flush, close, closed?, to: @io

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
      # The state machine itself lives on `Budget`; these are the driver's
      # handles on it. The lifecycle methods are `protected`: only the
      # dispatcher and codecs (the shared MQTT::Protocol namespace) may drive
      # the budget, so external code cannot desync it - misuse is a compile
      # error.

      protected def start_packet(remaining_length : UInt32) : Nil
        @budget.start(remaining_length)
      end

      protected def finish_packet : Nil
        @budget.finish
      end

      protected def abort_packet : Nil
        @budget.deactivate
      end

      # Bytes left to read in the current packet (0 outside a packet read).
      def remaining_in_packet : UInt32
        @budget.remaining
      end

      # Codec `from_io` entry guard. Parsing assumes an active byte budget
      # (normally started by `Packet.read_body`), but the per-packet `from_io`
      # methods are public and take an explicit `remaining_length` - a direct
      # call arms the budget from that argument so the parse is bounded the
      # same way instead of silently misparsing. No-op mid-packet, so the
      # dispatcher path is unaffected.
      protected def ensure_packet_budget(remaining_length : UInt32) : Nil
        @budget.ensure_started(remaining_length)
      end

      # Underlying read that returns nil at a clean end-of-stream (vs raising),
      # so the packet dispatcher can tell "connection closed" from "truncated
      # packet". Uncharged: only used for the fixed header's first byte, before
      # a packet is committed.
      def read_byte? : UInt8?
        @io.read_byte
      end

      def read_byte
        @budget.charge(sizeof(UInt8))
        @io.read_byte || raise ::IO::EOFError.new
      end

      def read_string(len : UInt16? = nil)
        len = read_int if len.nil?
        raise Error::PacketTooLarge.new(@max_packet_size, len) if len > @max_packet_size
        @budget.charge(len)
        str = @io.read_string(len)
        if str.includes?('\u0000') || !str.valid_encoding?
          raise MQTT::Protocol::Error::PacketDecode.new "Illformed UTF-8 string"
        end
        str
      end

      def read_int
        @budget.charge(sizeof(UInt16))
        UInt16.from_io(@io, @byte_format)
      end

      def read_four_byte_int : UInt32
        @budget.charge(sizeof(UInt32))
        UInt32.from_io(@io, @byte_format)
      end

      def read_string_pair : {String, String}
        key = read_string
        value = read_string
        {key, value}
      end

      # Variable Byte Integer (§1.5.5): up to four bytes, seven value bits
      # each with the MSB as a continuation flag. The encoding MUST be minimal
      # [MQTT-1.5.5-1], so a non-minimal encoding is rejected as malformed -
      # otherwise an overlong value desyncs the property consumed-counter.
      def read_variable_byte_int : UInt32
        multiplier : UInt32 = 1
        value : UInt32 = 0
        bytes_read = 0
        loop do
          @budget.charge(sizeof(UInt8))
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
        @budget.charge(len)
        bytes = Bytes.new(len)
        @io.read_fully(bytes)
        bytes
      end

      # Fill a caller-owned buffer (e.g. stack allocated) so a field that is
      # only inspected, not kept, needs no heap allocation.
      def read_fully(bytes : Bytes) : Nil
        @budget.charge(bytes.size)
        @io.read_fully(bytes)
      end

      # --- version-dependent framing hooks -----------------------------------
      #
      # Thin forwards to the `Framing` strategy, so packet codecs call a hook on
      # the IO and never branch on the version themselves. Every difference
      # between v3 and v5 wire framing lives in `Framing::V3` / `Framing::V5`;
      # the contract each hook fulfils is documented on `Framing::Base`.

      def read_properties(klass : T.class) : T forall T
        @framing.read_properties(self, klass)
      end

      # The PUBACK/PUBREC/PUBREL/PUBCOMP tail after the packet id: exactly a
      # reason tail offset by the 2 packet-id bytes (the caller asserts
      # remaining_length >= 2 before reading the id), so both versions share
      # one reason-tail parser - v3 asserts an empty tail, making the
      # dropped-gate bug (a v3 PUBREL misparsed as v5) structurally impossible.
      def read_ack_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
        read_reason_tail(remaining_length - PACKET_ID_BYTESIZE, properties_klass)
      end

      def read_reason_tail(remaining_length : UInt32, properties_klass : P.class) : {UInt8?, P} forall P
        @framing.read_reason_tail(self, remaining_length, properties_klass)
      end

      def write_properties(properties) : Nil
        @framing.write_properties(self, properties)
      end

      def write_ack(first_byte : UInt8, packet_id : UInt16, reason_value : UInt8, properties) : Nil
        @framing.write_ack(self, first_byte, packet_id, reason_value, properties)
      end

      def write_reason_tail(first_byte : UInt8, reason_value : UInt8, properties) : Nil
        @framing.write_reason_tail(self, first_byte, reason_value, properties)
      end

      delegate validate_subscription_options, validate_packet_type,
        validate_outbound_packet_type, suback_code_byte,
        read_connack_reason, read_suback_reason, connack_code_byte,
        allow_empty_topic?, unsuback_payload?, to: @framing

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

      # Variable Byte Integer (§1.5.5).
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
      # rule of 3.4.2.1 / 3.14.2.1 / 3.15.2.1: a zero (success/normal) reason
      # with no properties is omitted entirely, and the properties section is
      # omitted when empty and the reason is the last byte. The single source
      # of truth for this rule - both the remaining_length arithmetic and the
      # V5 writers derive from it, so the reported size can't drift from what
      # is written.
      def self.tail_bytesize(reason_value : UInt8, properties) : UInt32
        if reason_value.zero? && properties.empty?
          0u32
        elsif properties.empty?
          REASON_CODE_BYTESIZE
        else
          REASON_CODE_BYTESIZE + properties.bytesize
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

      # Version-dependent wire framing, as a strategy the IO swaps in place when
      # CONNECT reveals the version. Stateless, so one instance per version is
      # shared by every connection - switching framing allocates nothing.
      module Framing
        # The framing for `version`, from the shared instances.
        def self.for(version : Version) : Base
          case version
          in Version::Unknown then Bootstrap::INSTANCE
          in Version::V3_1    then V3::V3_1
          in Version::V3_1_1  then V3::V3_1_1
          in Version::V5      then V5::INSTANCE
          end
        end

        abstract class Base
          abstract def version : Version

          # The generic hooks (returning a parsed properties/reason type) need a
          # concrete base method because Crystal can't express an abstract def
          # with a free return type; both subclasses still override it, so the
          # base body is never reached.

          # Parse a properties section (on v3, where there is no section on the
          # wire, the struct's `v3_equivalent`). Bounds come from the packet byte
          # budget, so a peer cannot drive a read past the packet.
          def read_properties(io : IO, klass : T.class) : T forall T
            raise NotImplementedError.new("read_properties")
          end

          # The optional reason byte + properties tail of DISCONNECT / AUTH. Same
          # shape as the ack tail but with no packet id (so v3 expects an empty body).
          def read_reason_tail(io : IO, remaining_length : UInt32,
                               properties_klass : P.class) : {UInt8?, P} forall P
            raise NotImplementedError.new("read_reason_tail")
          end

          # Write a properties section; nothing on v3, where there is none.
          abstract def write_properties(io : IO, properties) : Nil

          # Write a whole PUBACK/PUBREC/PUBREL/PUBCOMP: header, packet id, and
          # on v5 the reason + properties tail, minus any part it may omit (§3.4.2.1).
          abstract def write_ack(io : IO, first_byte : UInt8, packet_id : UInt16,
                                 reason_value : UInt8, properties) : Nil

          # Write a whole DISCONNECT / AUTH: as `write_ack` with no packet id.
          abstract def write_reason_tail(io : IO, first_byte : UInt8,
                                         reason_value : UInt8, properties) : Nil

          # Validate a SUBSCRIBE option byte's version-reserved bits ([MQTT-3.8.3-5],
          # [MQTT-3.8.3-4 v3.1.1]).
          abstract def validate_subscription_options(options : UInt8) : Nil

          # Reject packet types that do not exist in this version, before any body
          # bytes are read. Keeps the version-blind dispatcher from parsing v5-only
          # packets on a v3 connection - and, before CONNECT, anything but a CONNECT.
          abstract def validate_packet_type(type : UInt8) : Nil

          # Write-side mirror of validate_packet_type: reject packet types this
          # version cannot put on the wire, raising before any byte is written.
          # Every packet's `to_io` calls it first.
          abstract def validate_outbound_packet_type(type : UInt8) : Nil

          # The SUBACK payload byte for this version: the v5 reason code, or on v3
          # the granted QoS or the single v3 failure code 0x80.
          abstract def suback_code_byte(reason_code : SubAck::ReasonCode) : UInt8

          # Interpret a CONNACK code byte: a v3 return code or a v5 reason code.
          abstract def read_connack_reason(byte : UInt8)

          # Interpret a SUBACK payload byte: v3 allows only the granted-QoS values
          # and 0x80 (Failure); v5 has the full reason-code set.
          abstract def read_suback_reason(byte : UInt8) : SubAck::ReasonCode

          # The CONNACK code byte for this version: a v3 return code or a v5
          # reason code. Connack#to_io resolves it BEFORE writing the header, so
          # an unmappable reason on v3 raises cleanly instead of leaving a
          # truncated packet on the wire.
          abstract def connack_code_byte(reason : Connack::ReasonCode) : UInt8

          # Whether an empty PUBLISH topic is legal (v5, resolved via a Topic Alias).
          abstract def allow_empty_topic? : Bool

          # Whether UNSUBACK carries a body beyond the packet id (v5: properties +
          # per-topic reason codes; v3: a bare packet id).
          abstract def unsuback_payload? : Bool
        end

        # MQTT 3.1 / 3.1.1 framing: no properties sections, no reason codes; the
        # ack/disconnect bodies are degenerate (bare packet id / empty). One
        # framing serves both v3 versions; the concrete negotiated version is
        # carried so `io.version` stays honest for 3.1 (MQIsdp) connections.
        class V3 < Base
          getter version : Version

          def initialize(@version : Version)
          end

          V3_1   = new(Version::V3_1)
          V3_1_1 = new(Version::V3_1_1)

          def read_properties(io : IO, klass : T.class) : T forall T
            klass.v3_equivalent
          end

          def write_properties(io : IO, properties) : Nil
          end

          def write_ack(io : IO, first_byte : UInt8, packet_id : UInt16,
                        reason_value : UInt8, properties) : Nil
            io.write_byte(first_byte)
            io.write_remaining_length(PACKET_ID_BYTESIZE)
            io.write_int(packet_id)
          end

          def read_reason_tail(io : IO, remaining_length : UInt32,
                               properties_klass : P.class) : {UInt8?, P} forall P
            unless remaining_length.zero?
              raise Error::PacketDecode.new "invalid length #{remaining_length} for v3"
            end
            {nil, properties_klass.v3_equivalent}
          end

          def write_reason_tail(io : IO, first_byte : UInt8, reason_value : UInt8, properties) : Nil
            io.write_byte(first_byte)
            io.write_remaining_length(0)
          end

          def validate_subscription_options(options : UInt8) : Nil
            # MQTT 3.1.1: only the two QoS bits are defined; bits 7-2 are reserved
            # and MUST be zero, otherwise the packet is malformed [MQTT-3.8.3-4 v3.1.1].
            # (v5 gives bits 2-5 meaning, so this rejection is v3-only.)
            unless (options & 0b1111_1100u8).zero?
              raise Error::PacketDecode.new "Malformed packet: reserved subscription option bits set"
            end
          end

          def validate_packet_type(type : UInt8) : Nil
            # Type 15 (AUTH) is Reserved/Forbidden in v3 (Table 2.1, section
            # 2.2.1); a violation closes the connection per [MQTT-4.8.0-1 v3.1.1].
            if type == Auth::TYPE
              raise Error::PacketDecode.new "invalid packet type #{type}"
            end
          end

          def validate_outbound_packet_type(type : UInt8) : Nil
            if type == Auth::TYPE
              raise Error::PacketEncode.new "cannot encode AUTH on a v3 connection"
            end
          end

          def suback_code_byte(reason_code : SubAck::ReasonCode) : UInt8
            # Only the granted-QoS values and 0x80 Failure exist in a v3.1.1
            # SUBACK payload [MQTT-3.9.3-2 v3.1.1], and every v5 reason that grants
            # nothing is a failure.
            reason_code.value <= 2 ? reason_code.value : 0x80u8
          end

          def read_connack_reason(byte : UInt8)
            unless byte < 6
              raise Error::PacketDecode.new "invalid return code: #{byte}"
            end
            Connack::ReasonCode.from_v3_return_code(Connack::ReturnCode.new(byte))
          end

          def read_suback_reason(byte : UInt8) : SubAck::ReasonCode
            # v3.1.1 SUBACK return codes are 0-2 (granted QoS) or 0x80 Failure
            # [MQTT-3.9.3-2 v3.1.1]; 0x80 maps onto the v5 UnspecifiedError member.
            unless byte <= 2 || byte == 0x80
              raise Error::PacketDecode.new "invalid suback return code #{byte}"
            end
            SubAck::ReasonCode.new(byte)
          end

          def connack_code_byte(reason : Connack::ReasonCode) : UInt8
            return_code = reason.to_v3_return_code ||
                          raise Error::PacketEncode.new("no v3 return code for #{reason}")
            return_code.value
          end

          def allow_empty_topic? : Bool
            false
          end

          def unsuback_payload? : Bool
            false
          end
        end

        # The pre-CONNECT state of an IO: the version is not known yet, so only
        # a CONNECT may be read ([MQTT-3.1.0-1]) and it is the CONNECT codec
        # that replaces this framing.
        #
        # Writes are limited to the two packets that make sense without a
        # version: a CONNECT, which negotiates one, and a CONNACK rejecting the
        # connection. That CONNACK inherits v3 framing deliberately: a client
        # whose version we could not determine gets the v3 return code
        # ([MQTT-3.1.2-2]). Anything else needs an IO pinned to a version.
        class Bootstrap < V3
          def initialize
            super(Version::Unknown)
          end

          INSTANCE = new

          def validate_packet_type(type : UInt8) : Nil
            # [MQTT-3.1.0-1]: the first packet MUST be a CONNECT. Rejected here,
            # before any body byte is read, so a packet of unknown version can
            # never be parsed with a guessed framing.
            unless type == Connect::TYPE
              raise Error::PacketDecode.new "first packet must be CONNECT, got type #{type}"
            end
          end

          def validate_outbound_packet_type(type : UInt8) : Nil
            unless type == Connect::TYPE || type == Connack::TYPE
              raise Error::PacketEncode.new "cannot encode packet type #{type} before the version is negotiated"
            end
          end
        end

        # MQTT 5.0 framing: properties sections and reason codes throughout.
        class V5 < Base
          INSTANCE = new

          def version : Version
            Version::V5
          end

          def read_properties(io : IO, klass : T.class) : T forall T
            klass.from_io(io, io.remaining_in_packet)
          end

          def write_properties(io : IO, properties) : Nil
            properties.to_io(io)
          end

          def write_ack(io : IO, first_byte : UInt8, packet_id : UInt16,
                        reason_value : UInt8, properties) : Nil
            io.write_byte(first_byte)
            tail = IO.tail_bytesize(reason_value, properties)
            io.write_remaining_length(PACKET_ID_BYTESIZE + tail)
            io.write_int(packet_id)
            io.write_byte(reason_value) unless tail.zero?
            properties.to_io(io) if tail > REASON_CODE_BYTESIZE
          end

          # As the ack tail but with no packet id: empty body => default reason +
          # no properties; one byte => bare reason; more => reason + properties.
          def read_reason_tail(io : IO, remaining_length : UInt32,
                               properties_klass : P.class) : {UInt8?, P} forall P
            return {nil, properties_klass.new} if remaining_length.zero?
            reason = io.read_byte
            return {reason, properties_klass.new} if remaining_length == REASON_CODE_BYTESIZE
            # Exact consumption enforced by the byte budget + finish_packet.
            {reason, properties_klass.from_io(io, io.remaining_in_packet)}
          end

          def write_reason_tail(io : IO, first_byte : UInt8, reason_value : UInt8, properties) : Nil
            io.write_byte(first_byte)
            tail = IO.tail_bytesize(reason_value, properties)
            io.write_remaining_length(tail)
            io.write_byte(reason_value) unless tail.zero?
            properties.to_io(io) if tail > REASON_CODE_BYTESIZE
          end

          def validate_subscription_options(options : UInt8) : Nil
            if (options & 0b1100_0000u8) != 0
              raise Error::ProtocolError.new(0x81u8, "reserved subscription option bits set")
            end
          end

          def validate_packet_type(type : UInt8) : Nil
          end

          def validate_outbound_packet_type(type : UInt8) : Nil
          end

          def suback_code_byte(reason_code : SubAck::ReasonCode) : UInt8
            reason_code.value
          end

          def read_connack_reason(byte : UInt8)
            Connack::ReasonCode.from_value?(byte) ||
              raise Error::ProtocolError.new(0x81u8, "invalid connack reason code #{byte}")
          end

          def read_suback_reason(byte : UInt8) : SubAck::ReasonCode
            SubAck::ReasonCode.from_value?(byte) ||
              raise Error::ProtocolError.new(0x81u8, "invalid suback reason code #{byte}")
          end

          def connack_code_byte(reason : Connack::ReasonCode) : UInt8
            reason.value
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
end
