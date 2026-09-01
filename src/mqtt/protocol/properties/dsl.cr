require "../io"

module MQTT
  module Protocol
    alias StringPair = {String, String}

    # A property value encoded as a Variable Byte Integer (MQTT-1.5.5). It is
    # the `UInt32` the wire form decodes to, under a name `prop` can tell apart
    # from a fixed-width four byte integer.
    alias VarInt = UInt32

    # The codec for an MQTT 5.0 property section (MQTT5_FINDINGS.md 3.4).
    #
    # Each packet type gets its own struct, so a property that is illegal in
    # that packet is structurally absent. A property is one `prop`:
    #
    #     struct ConnackProperties
    #       include Properties
    #
    #       prop session_expiry_interval : UInt32?, id: 0x11
    #
    #       # 3.2.2.3.4: a value other than 0 or 1 is a Protocol Error.
    #       prop maximum_qos : UInt8?, id: 0x24, range: 0..1
    #     end
    #
    # That is the whole struct: `prop` writes the instance variable, the getter
    # and a setter that enforces the declared range, and including this module
    # adds `initialize`, `bytesize`, `to_io` and `from_io`, all derived from the
    # declarations. The initializer takes named arguments only - a property
    # section is a bag of optional fields, where positional order would be
    # nothing but a trap.
    #
    # The declared type picks the wire encoding:
    #
    #     Bool        one byte, 0 or 1
    #     UInt8       one byte
    #     UInt16      two byte integer
    #     UInt32      four byte integer
    #     VarInt      variable byte integer
    #     String      UTF-8 encoded string
    #     Bytes       binary data
    #     StringPair  UTF-8 string pair
    #     Array(T)    a repeatable property: a T, zero or more times
    #
    # Every property is optional, so every type is nilable and `nil` means
    # "absent from the section". The MQTT default for an absent property
    # (Maximum QoS 2, Retain Available 1, ...) is deliberately *not* stored as a
    # field default: a struct holding it could not tell "defaulted" from "sent
    # by the peer", and encoding it would put bytes on the wire the application
    # never asked for.
    #
    # A range is enforced in both directions: the decoder rejects an
    # out-of-range value as a Protocol Error (0x82), and the generated setter
    # (so also the initializer) raises `ArgumentError`, which is what stops the
    # shard from ever building a packet its own decoder would reject.
    #
    # User Property (0x26) is repeatable and legal in every packet that has a
    # properties section, and its order (including duplicate keys) MUST be
    # preserved - hence an `Array(StringPair)` and not a Hash. It is the one
    # property every struct has, and each declares it explicitly, so a struct
    # body always lists everything that packet can carry.
    #
    # The struct knows how to encode/decode itself (including its own Variable
    # Byte Integer length prefix) and to report its `bytesize` for
    # remaining-length precompute - no serialise-then-measure. Crystal's Struct
    # gives value `==`/`hash` over all fields for free, so round-trips compare.
    module Properties
      # The property types a declaration may name, and which of them are
      # integers (only an integer can carry a range). These are the
      # declaration's own spelling, which is how `VarInt` stays distinct from
      # the `UInt32` it is an alias for.
      # :nodoc:
      TYPES = ["Bool", "UInt8", "UInt16", "UInt32", "VarInt", "String", "Bytes", "StringPair"]
      # :nodoc:
      INTEGER_TYPES = ["UInt8", "UInt16", "UInt32", "VarInt"]

      # Everything one `prop` declared, keyed by struct name: name, type,
      # encoding, repeatability, wire identifier and range.
      #
      # A macro cannot hand macro variables back to its caller, so whatever is
      # generated for the struct as a whole reads the declarations back from
      # here: the codec below, and the initializer - whose signature has to
      # exist before any method body is analysed - in a `finished` hook.
      #
      # Compile-time state only; nothing reads it at runtime.
      # :nodoc:
      REGISTRY = {} of Nil => Nil

      macro included
        macro finished
          generate_initializer
        end

        # Parse a properties section, bounded by `remaining` - the bytes left in
        # the enclosing packet at this point. Parsing is instance-side (see
        # `#decode_properties`), so this is the door into it.
        def self.from_io(io : MQTT::Protocol::IO, remaining : UInt32) : self
          props = new
          props.decode_properties(io, remaining)
          props
        end
      end

      # Declare one property:
      #
      #     prop <name> : <Type>?, id: <byte>, range: <range>
      #
      #     id     the property identifier (2.2.2.2, Table 2.4), written as an
      #            unsuffixed literal in 0x01..0x7f
      #     range  optional value constraint; outside it is a Protocol Error
      #
      # Everything else - the encoding, whether the property repeats - follows
      # from the declared type. Writes the instance variable, the reader, and a
      # setter that enforces the range. A declaration is checked here, as it
      # expands - the message names the property, since a macro raise points at
      # the enclosing struct - so a struct that is never encoded is checked
      # just the same.
      macro prop(decl, *, id = nil, range = nil)
        {%
          key = @type.name.stringify
          table = MQTT::Protocol::Properties::REGISTRY
          table[key] = [] of Nil unless table[key]

          name = decl.var.stringify
          type = decl.type
          # `Nil` gains its global-scope prefix when a declaration is emitted
          # from another macro rather than written out, so both spellings have
          # to count as nil here.
          nils = ["Nil", "::Nil"]
          optional = type.is_a?(Union) && type.types.any? { |t| nils.includes?(t.stringify) }
          base = optional ? type.types.reject { |t| nils.includes?(t.stringify) }.first : type
          # Only Array(T) repeats; any other generic (a `Slice(UInt8)` written
          # out instead of `Bytes`, say) falls through to the encoding check
          # below, which names it in the error.
          repeated = base.is_a?(Generic) && base.name.stringify == "Array"
          element = repeated ? base.type_vars[0] : base
          element_name = element.stringify

          prop_name = "#{@type}##{name.id}".id
          raise "#{prop_name}: no MQTT property encoding for #{element}" unless MQTT::Protocol::Properties::TYPES.includes?(element_name)
          raise "#{prop_name} is declared twice" if table[key].any? { |other| other[:name] == name }
          raise "#{prop_name}: every property is optional, declare it as #{base}?" unless optional
          raise "#{prop_name}: needs an id:, or it would never reach the wire" if id.nil?
          # An identifier is a Variable Byte Integer (2.2.2.2), but both the
          # encoder's `write_byte` and the decoder's `when` arm are one byte
          # wide, so a one byte VBI is the whole range available here - roomy,
          # since no assigned identifier comes near 0x7f.
          raise "#{prop_name}: id must be an integer literal, got #{id}" unless id.is_a?(NumberLiteral)
          raise "#{prop_name}: id must be a whole number, got #{id}" if id.kind == :f32 || id.kind == :f64
          # Insisting on the plain spelling is not tidiness: a literal carries
          # its type, so `0x11u8` is neither `==` to `0x11` (the duplicate check
          # below would miss the collision) nor pastable - it expands to
          # `17_u8u8`, a syntax error blamed on this DSL rather than on the
          # declaration. An unsuffixed literal stringifies as a bare decimal,
          # which makes both safe.
          raise "#{prop_name}: id must be unsuffixed (0x11, not #{id}); the u8 is the DSL's job" unless id.kind == :i32
          raise "#{prop_name}: id #{id} is not a property identifier, they run 0x01..0x7f" unless 1 <= id && id <= 127
          if range
            # Bool is not an integer type either, but "drop it" is the useful
            # advice there, so it answers first.
            raise "#{prop_name}: a Bool property is already constrained to 0/1, drop the range" if element_name == "Bool"
            raise "#{prop_name}: a range is only enforceable on an integer property" unless MQTT::Protocol::Properties::INTEGER_TYPES.includes?(element_name)
          end
          # Every id is a bare decimal by now, so identifiers compare as numbers:
          # 0x11 and 17 are the same id.
          if other = table[key].find { |o| o[:id] == id }
            raise "#{@type}: #{other[:name].id} and #{name.id} declare the same property identifier"
          end

          table[key] << {name: name, type: type, base: base, element: element,
                         element_name: element_name, repeated: repeated,
                         id: id, range: range}
        %}

        @{{ name.id }} : {{ type }} = nil

        {% if repeated %}
          # The repeatable properties are nil-backed so decoding or constructing
          # a packet without them allocates nothing (the common case on the hot
          # path). These are value structs: the getter does NOT memoize (a read
          # never mutates, so `==` stays stable across reads and copies), which
          # also means appending to the getter's result is not supported - build
          # the array and assign it whole via the setter. Use the nilable `?`
          # reader to inspect without allocating.
          def {{ name.id }} : {{ base }}
            @{{ name.id }} || {{ base }}.new
          end

          def {{ name.id }}? : {{ type }}
            @{{ name.id }}
          end

          def {{ name.id }}=(value : {{ type }}) : {{ type }}
            {% if range %}
            value.try &.each do |element|
              unless ({{ range }}).includes?(element)
                raise ArgumentError.new("{{ name.id }} must be in {{ range }}, got #{element}")
              end
            end
            {% end %}
            # Empty normalises to nil so a constructed instance compares equal
            # to a decoded one (struct value equality is over the raw fields).
            @{{ name.id }} = value.try { |list| list.empty? ? nil : list }
          end
        {% else %}
          def {{ name.id }} : {{ type }}
            @{{ name.id }}
          end

          def {{ name.id }}=(value : {{ type }}) : {{ type }}
            {% if range %}
            unless value.nil? || ({{ range }}).includes?(value)
              raise ArgumentError.new("{{ name.id }} must be in {{ range }}, got #{value}")
            end
            {% end %}
            @{{ name.id }} = value
          end
        {% end %}
      end

      # Emit the named-argument initializer. Invoked from the `finished` hook
      # installed by `included`, never by hand: it needs every `prop` in the
      # body to have expanded first.
      macro generate_initializer
        {% specs = MQTT::Protocol::Properties::REGISTRY[@type.name.stringify] || [] of Nil %}
        {% ordered = specs.reject { |s| s[:repeated] } + specs.select { |s| s[:repeated] } %}

        def initialize(*,
                       {% for s in ordered %}
                       {{ s[:name].id }} : {{ s[:type] }} = nil,
                       {% end %})
          # Through the setters: they hold the range checks and the
          # empty-array-to-nil normalisation.
          {% for s in ordered %}
          self.{{ s[:name].id }} = {{ s[:name].id }}
          {% end %}
        end
      end

      # --- wire forms ---------------------------------------------------------
      #
      # One overload per property encoding, dispatched on the declared type, so
      # the compiler checks each of them and adding a property type means adding
      # three neighbouring methods. A Variable Byte Integer cannot join them -
      # `VarInt` is an alias of `UInt32`, so the two would be one overload - so
      # the generated code calls the VBI primitives directly for that one type.

      private def write_property(io : MQTT::Protocol::IO, value : Bool) : Nil
        io.write_byte(value ? 1u8 : 0u8)
      end

      private def write_property(io : MQTT::Protocol::IO, value : UInt8) : Nil
        io.write_byte(value)
      end

      private def write_property(io : MQTT::Protocol::IO, value : UInt16) : Nil
        io.write_int(value)
      end

      private def write_property(io : MQTT::Protocol::IO, value : UInt32) : Nil
        io.write_four_byte_int(value)
      end

      private def write_property(io : MQTT::Protocol::IO, value : String) : Nil
        io.write_string(value)
      end

      private def write_property(io : MQTT::Protocol::IO, value : Bytes) : Nil
        io.write_bytes(value)
      end

      private def write_property(io : MQTT::Protocol::IO, value : StringPair) : Nil
        io.write_string_pair(value[0], value[1])
      end

      # No `Bool` reader: a boolean property's 0/1 rule is a Protocol Error the
      # decoder reports with the offending identifier, so it reads the byte and
      # checks it there.
      private def read_property(io : MQTT::Protocol::IO, type : UInt8.class) : UInt8
        io.read_byte
      end

      private def read_property(io : MQTT::Protocol::IO, type : UInt16.class) : UInt16
        io.read_int
      end

      private def read_property(io : MQTT::Protocol::IO, type : UInt32.class) : UInt32
        io.read_four_byte_int
      end

      private def read_property(io : MQTT::Protocol::IO, type : String.class) : String
        io.read_string
      end

      private def read_property(io : MQTT::Protocol::IO, type : Bytes.class) : Bytes
        io.read_bytes
      end

      private def read_property(io : MQTT::Protocol::IO, type : StringPair.class) : StringPair
        io.read_string_pair
      end

      # Bytes one value occupies on the wire, excluding its identifier. Serves
      # both the encoder (precompute) and the decoder (bytes consumed).
      private def property_bytesize(value : Bool | UInt8) : Int32
        1
      end

      private def property_bytesize(value : UInt16) : Int32
        2
      end

      private def property_bytesize(value : UInt32) : Int32
        4
      end

      private def property_bytesize(value : String) : Int32
        2 + value.bytesize
      end

      private def property_bytesize(value : Bytes) : Int32
        2 + value.size
      end

      private def property_bytesize(value : StringPair) : Int32
        2 + value[0].bytesize + 2 + value[1].bytesize
      end

      # --- generated codec ----------------------------------------------------
      #
      # Each method starts from the same lookup: the declarations from
      # `REGISTRY`, scalars first in declaration order and then the repeatable
      # ones. Property order within a section is the encoder's choice
      # (2.2.2.1), but a fixed one keeps encodes reproducible.

      # Whether this section puts any bytes on the wire beyond its own (zero)
      # length prefix - which is exactly "no property is set".
      def empty? : Bool
        body_bytesize.zero?
      end

      # Size of the property body, excluding its own length prefix.
      private def body_bytesize : Int32
        {% begin %}
          {% specs = MQTT::Protocol::Properties::REGISTRY[@type.name.stringify] || [] of Nil %}
          {% ordered = specs.reject { |s| s[:repeated] } + specs.select { |s| s[:repeated] } %}
          size = 0
          {% for s in ordered %}
          {% var_int = s[:element_name] == "VarInt" %}
          {% if s[:repeated] %}
          if list = @{{ s[:name].id }}
            list.each do |value|
              size += 1 # identifier
              size += {% if var_int %}MQTT::Protocol::IO.variable_byte_int_size(value){% else %}property_bytesize(value){% end %}
            end
          end
          {% else %}
          unless (value = @{{ s[:name].id }}).nil?
            size += 1 # identifier
            size += {% if var_int %}MQTT::Protocol::IO.variable_byte_int_size(value){% else %}property_bytesize(value){% end %}
          end
          {% end %}
          {% end %}
          size
        {% end %}
      end

      # Total wire size including the Variable Byte Integer length prefix.
      def bytesize : Int32
        body = body_bytesize
        MQTT::Protocol::IO.variable_byte_int_size(body) + body
      end

      def to_io(io : MQTT::Protocol::IO) : Nil
        {% begin %}
          {% specs = MQTT::Protocol::Properties::REGISTRY[@type.name.stringify] || [] of Nil %}
          {% ordered = specs.reject { |s| s[:repeated] } + specs.select { |s| s[:repeated] } %}
          io.write_variable_byte_int(body_bytesize)
          {% for s in ordered %}
          {% var_int = s[:element_name] == "VarInt" %}
          {% if s[:repeated] %}
          if list = @{{ s[:name].id }}
            list.each do |value|
              io.write_byte {{ s[:id] }}u8
              {% if var_int %}io.write_variable_byte_int(value){% else %}write_property(io, value){% end %}
            end
          end
          {% else %}
          unless (value = @{{ s[:name].id }}).nil?
            io.write_byte {{ s[:id] }}u8
            {% if var_int %}io.write_variable_byte_int(value){% else %}write_property(io, value){% end %}
          end
          {% end %}
          {% end %}
        {% end %}
      end

      # Read a properties section into this instance. The declared section
      # length is checked against `remaining` - the bytes left in the enclosing
      # packet - before any field is read, so a packet cannot make the parser
      # read past its own boundary (and a small packet cannot declare a huge
      # property section).
      protected def decode_properties(io : MQTT::Protocol::IO, remaining : UInt32) : Nil
        {% begin %}
          {% specs = MQTT::Protocol::Properties::REGISTRY[@type.name.stringify] || [] of Nil %}
          {% ordered = specs.reject { |s| s[:repeated] } + specs.select { |s| s[:repeated] } %}
          # Direct calls (outside Packet.read_body) arm the byte budget from the
          # explicit bound so field reads cannot over-read past it.
          io.ensure_packet_budget(remaining)
          total = io.read_variable_byte_int.to_i
          prefix = MQTT::Protocol::IO.variable_byte_int_size(total)
          if prefix + total > remaining.to_i
            raise Error::ProtocolError.new(0x81u8, "properties length #{total} exceeds #{remaining} bytes remaining")
          end
          consumed = 0
          while consumed < total
            id = io.read_byte
            consumed += 1
            case id
            {% for s in ordered %}
            {% var_int = s[:element_name] == "VarInt" %}
            when {{ s[:id] }}u8
              {% unless s[:repeated] %}
              unless @{{ s[:name].id }}.nil?
                raise Error::ProtocolError.new(0x82u8, "duplicate property 0x#{id.to_s(16)}")
              end
              {% end %}
              {% if s[:element_name] == "Bool" %}
              value = io.read_byte
              # A boolean property with a value other than 0 or 1 is a Protocol
              # Error (3.1.2.11.6/3.1.2.11.7 Request Response/Problem
              # Information, 3.2.2.3.5 Retain Available, ...). Exception:
              # 3.3.2.3.2 Payload Format Indicator states no such rule;
              # rejecting non-0/1 there too is an intentional deviation, resting
              # on the generic malformed-packet reasoning of 2.4.
              unless value <= 1u8
                raise Error::ProtocolError.new(0x82u8, "property 0x#{id.to_s(16)} must be 0 or 1, got #{value}")
              end
              {% elsif var_int %}
              value = io.read_variable_byte_int
              {% else %}
              value = read_property(io, {{ s[:element] }})
              {% end %}
              consumed += {% if var_int %}MQTT::Protocol::IO.variable_byte_int_size(value){% else %}property_bytesize(value){% end %}
              {% if s[:range] %}
              # Declared value constraint: out of range is a Protocol Error.
              # Checked before assigning so the wire error is 0x82, not the
              # setter's ArgumentError (that one is for local construction).
              unless ({{ s[:range] }}).includes?(value)
                raise Error::ProtocolError.new(0x82u8, "property 0x#{id.to_s(16)} value #{value} out of range {{ s[:range] }}")
              end
              {% end %}
              {% if s[:repeated] %}
              (@{{ s[:name].id }} ||= {{ s[:base] }}.new) << value
              {% elsif s[:element_name] == "Bool" %}
              @{{ s[:name].id }} = value == 1u8
              {% else %}
              @{{ s[:name].id }} = value
              {% end %}
            {% end %}
            else
              raise Error::ProtocolError.new(0x81u8, "unknown property 0x#{id.to_s(16)}")
            end
          end
          unless consumed == total
            raise Error::ProtocolError.new(0x81u8, "malformed properties: read #{consumed} of #{total} bytes")
          end
        {% end %}
      end
    end
  end
end
