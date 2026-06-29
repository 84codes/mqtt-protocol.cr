require "./io"

module MQTT
  module Protocol
    alias StringPair = {String, String}

    # Generates a typed MQTT 5.0 properties struct (MQTT5_FINDINGS.md 3.4).
    #
    # Each `spec` is a `{name, identifier, kind}` tuple describing one scalar
    # (non-repeatable) property. `kind` is one of: :byte_bool, :byte_int,
    # :two_byte_int, :four_byte_int, :string, :binary, :var_int. Pass
    # :sub_id_list as the kind to declare the repeatable Subscription
    # Identifier array (PUBLISH only).
    #
    # User Property (0x26) is valid in every packet, so it is always present as
    # an ordered `user_properties : Array(StringPair)` and never listed in the
    # specs.
    #
    # The generated struct knows how to encode/decode itself (including its own
    # Variable Byte Integer length prefix) and to report its `bytesize` for
    # remaining-length precompute - no serialise-then-measure. Crystal's Struct
    # gives value `==`/`hash` over all fields for free, so round-trips compare.
    macro define_properties(name, *specs)
      struct {{name}}
        {% types = {:byte_bool => Bool, :byte_int => UInt8, :two_byte_int => UInt16,
                    :four_byte_int => UInt32, :string => String, :binary => Bytes,
                    :var_int => UInt32} %}
        {% singles = specs.select { |s| s[2] != :sub_id_list } %}
        {% has_sub_ids = specs.any? { |s| s[2] == :sub_id_list } %}

        {% for s in singles %}
        property {{ s[0].id }} : {{ types[s[2]] }}?
        {% end %}
        property user_properties : Array(StringPair)
        {% if has_sub_ids %}
        property subscription_identifiers : Array(UInt32)
        {% end %}

        def initialize(
          {% for s in singles %}
          @{{ s[0].id }} : {{ types[s[2]] }}? = nil,
          {% end %}
          @user_properties : Array(StringPair) = [] of StringPair,
          {% if has_sub_ids %}
          @subscription_identifiers : Array(UInt32) = [] of UInt32,
          {% end %}
        )
        end

        def empty? : Bool
          {% for s in singles %}@{{ s[0].id }}.nil? && {% end %}user_properties.empty?{% if has_sub_ids %} && subscription_identifiers.empty?{% end %}
        end

        # Size of the property body, excluding its own length prefix.
        private def body_bytesize : Int32
          size = 0
          {% for s in singles %}
          unless (v = @{{ s[0].id }}).nil?
            size += 1 # identifier
            {% k = s[2] %}
            {% if k == :byte_bool || k == :byte_int %} size += 1
            {% elsif k == :two_byte_int %} size += 2
            {% elsif k == :four_byte_int %} size += 4
            {% elsif k == :string %} size += 2 + v.bytesize
            {% elsif k == :binary %} size += 2 + v.size
            {% elsif k == :var_int %} size += MQTT::Protocol::IO.variable_byte_int_size(v)
            {% end %}
          end
          {% end %}
          user_properties.each do |(key, value)|
            size += 1 + 2 + key.bytesize + 2 + value.bytesize
          end
          {% if has_sub_ids %}
          subscription_identifiers.each do |sub_id|
            size += 1 + MQTT::Protocol::IO.variable_byte_int_size(sub_id)
          end
          {% end %}
          size
        end

        # Total wire size including the Variable Byte Integer length prefix.
        def bytesize : Int32
          body = body_bytesize
          MQTT::Protocol::IO.variable_byte_int_size(body) + body
        end

        def to_io(io : MQTT::Protocol::IO) : Nil
          io.write_variable_byte_int(body_bytesize)
          {% for s in singles %}
          unless (v = @{{ s[0].id }}).nil?
            io.write_byte {{ s[1] }}u8
            {% k = s[2] %}
            {% if k == :byte_bool %} io.write_byte(v ? 1u8 : 0u8)
            {% elsif k == :byte_int %} io.write_byte(v)
            {% elsif k == :two_byte_int %} io.write_int(v)
            {% elsif k == :four_byte_int %} io.write_four_byte_int(v)
            {% elsif k == :string %} io.write_string(v)
            {% elsif k == :binary %} io.write_bytes(v)
            {% elsif k == :var_int %} io.write_variable_byte_int(v)
            {% end %}
          end
          {% end %}
          user_properties.each do |(key, value)|
            io.write_byte 0x26u8
            io.write_string_pair(key, value)
          end
          {% if has_sub_ids %}
          subscription_identifiers.each do |sub_id|
            io.write_byte 0x0Bu8
            io.write_variable_byte_int(sub_id)
          end
          {% end %}
        end

        # Parse a properties section, bounded by `remaining` - the bytes left in
        # the enclosing packet at this point. The declared section length is
        # checked against that budget before any field is read, so a packet
        # cannot make the parser read past its own boundary (and a small packet
        # cannot declare a huge property section).
        def self.from_io(io : MQTT::Protocol::IO, remaining : UInt32) : self
          props = new
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
            {% for s in singles %}
            when {{ s[1] }}u8
              unless props.{{ s[0].id }}.nil?
                raise Error::ProtocolError.new(0x82u8, "duplicate property 0x#{id.to_s(16)}")
              end
              {% k = s[2] %}
              {% if k == :byte_bool %}
                props.{{ s[0].id }} = io.read_byte != 0u8
                consumed += 1
              {% elsif k == :byte_int %}
                props.{{ s[0].id }} = io.read_byte
                consumed += 1
              {% elsif k == :two_byte_int %}
                props.{{ s[0].id }} = io.read_int
                consumed += 2
              {% elsif k == :four_byte_int %}
                props.{{ s[0].id }} = io.read_four_byte_int
                consumed += 4
              {% elsif k == :string %}
                str = io.read_string
                props.{{ s[0].id }} = str
                consumed += 2 + str.bytesize
              {% elsif k == :binary %}
                bytes = io.read_bytes
                props.{{ s[0].id }} = bytes
                consumed += 2 + bytes.size
              {% elsif k == :var_int %}
                val = io.read_variable_byte_int
                props.{{ s[0].id }} = val
                consumed += MQTT::Protocol::IO.variable_byte_int_size(val)
              {% end %}
            {% end %}
            when 0x26u8
              pair = io.read_string_pair
              props.user_properties << pair
              consumed += 2 + pair[0].bytesize + 2 + pair[1].bytesize
            {% if has_sub_ids %}
            when 0x0Bu8
              val = io.read_variable_byte_int
              props.subscription_identifiers << val
              consumed += MQTT::Protocol::IO.variable_byte_int_size(val)
            {% end %}
            else
              raise Error::ProtocolError.new(0x81u8, "unknown property 0x#{id.to_s(16)}")
            end
          end
          unless consumed == total
            raise Error::ProtocolError.new(0x81u8, "malformed properties: read #{consumed} of #{total} bytes")
          end
          props
        end
      end
    end

    define_properties(ConnectProperties,
      {:session_expiry_interval, 0x11, :four_byte_int},
      {:receive_maximum, 0x21, :two_byte_int},
      {:maximum_packet_size, 0x27, :four_byte_int},
      {:topic_alias_maximum, 0x22, :two_byte_int},
      {:request_response_information, 0x19, :byte_bool},
      {:request_problem_information, 0x17, :byte_bool},
      {:authentication_method, 0x15, :string},
      {:authentication_data, 0x16, :binary},
    )

    define_properties(WillProperties,
      {:will_delay_interval, 0x18, :four_byte_int},
      {:payload_format_indicator, 0x01, :byte_bool},
      {:message_expiry_interval, 0x02, :four_byte_int},
      {:content_type, 0x03, :string},
      {:response_topic, 0x08, :string},
      {:correlation_data, 0x09, :binary},
    )

    define_properties(ConnackProperties,
      {:session_expiry_interval, 0x11, :four_byte_int},
      {:receive_maximum, 0x21, :two_byte_int},
      {:maximum_qos, 0x24, :byte_int},
      {:retain_available, 0x25, :byte_bool},
      {:maximum_packet_size, 0x27, :four_byte_int},
      {:assigned_client_identifier, 0x12, :string},
      {:topic_alias_maximum, 0x22, :two_byte_int},
      {:reason_string, 0x1F, :string},
      {:wildcard_subscription_available, 0x28, :byte_bool},
      {:subscription_identifier_available, 0x29, :byte_bool},
      {:shared_subscription_available, 0x2A, :byte_bool},
      {:server_keep_alive, 0x13, :two_byte_int},
      {:response_information, 0x1A, :string},
      {:server_reference, 0x1C, :string},
      {:authentication_method, 0x15, :string},
      {:authentication_data, 0x16, :binary},
    )

    define_properties(PublishProperties,
      {:payload_format_indicator, 0x01, :byte_bool},
      {:message_expiry_interval, 0x02, :four_byte_int},
      {:topic_alias, 0x23, :two_byte_int},
      {:response_topic, 0x08, :string},
      {:correlation_data, 0x09, :binary},
      {:content_type, 0x03, :string},
      {:subscription_identifiers, 0x0B, :sub_id_list},
    )

    define_properties(SubscribeProperties,
      {:subscription_identifier, 0x0B, :var_int},
    )

    define_properties(DisconnectProperties,
      {:session_expiry_interval, 0x11, :four_byte_int},
      {:reason_string, 0x1F, :string},
      {:server_reference, 0x1C, :string},
    )

    define_properties(AuthProperties,
      {:authentication_method, 0x15, :string},
      {:authentication_data, 0x16, :binary},
      {:reason_string, 0x1F, :string},
    )

    # Ack-packet properties: Reason String + User Property (3.4.2.2 etc.).
    define_properties(PubAckProperties, {:reason_string, 0x1F, :string})
    define_properties(SubAckProperties, {:reason_string, 0x1F, :string})
    define_properties(UnsubAckProperties, {:reason_string, 0x1F, :string})

    # Unsubscribe carries only User Property (3.10.2.1).
    define_properties(UnsubscribeProperties)
  end
end
