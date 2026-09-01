require "./properties/dsl"

module MQTT
  module Protocol
    # The property sections of MQTT 5.0, one struct per packet type: a property
    # that is illegal in a packet is absent from its struct, so it cannot be
    # constructed or decoded there. See `Properties` for what `prop` generates
    # and what its `id:` and `range:` carry.
    #
    # User Property (0x26) is legal in every one of these, so every struct
    # declares it after its own scalar properties - which is also where it sits
    # on the wire.

    struct ConnectProperties
      include Properties

      prop session_expiry_interval : UInt32?, id: 0x11
      # 3.1.2.11.3: a Receive Maximum of 0 is a Protocol Error.
      prop receive_maximum : UInt16?, id: 0x21, range: 1..65535
      # 3.1.2.11.4: a Maximum Packet Size of 0 is a Protocol Error.
      prop maximum_packet_size : UInt32?, id: 0x27, range: 1..4294967295
      prop topic_alias_maximum : UInt16?, id: 0x22
      prop request_response_information : Bool?, id: 0x19
      prop request_problem_information : Bool?, id: 0x17
      prop authentication_method : String?, id: 0x15
      prop authentication_data : Bytes?, id: 0x16
      prop user_properties : Array(StringPair)?, id: 0x26
    end

    struct WillProperties
      include Properties

      prop will_delay_interval : UInt32?, id: 0x18
      prop payload_format_indicator : Bool?, id: 0x01
      prop message_expiry_interval : UInt32?, id: 0x02
      prop content_type : String?, id: 0x03
      prop response_topic : String?, id: 0x08
      prop correlation_data : Bytes?, id: 0x09
      prop user_properties : Array(StringPair)?, id: 0x26
    end

    struct ConnackProperties
      include Properties

      prop session_expiry_interval : UInt32?, id: 0x11
      # 3.2.2.3.3: a Receive Maximum of 0 is a Protocol Error.
      prop receive_maximum : UInt16?, id: 0x21, range: 1..65535
      # 3.2.2.3.4: only 0 or 1.
      prop maximum_qos : UInt8?, id: 0x24, range: 0..1
      prop retain_available : Bool?, id: 0x25
      # 3.2.2.3.6: a Maximum Packet Size of 0 is a Protocol Error.
      prop maximum_packet_size : UInt32?, id: 0x27, range: 1..4294967295
      prop assigned_client_identifier : String?, id: 0x12
      prop topic_alias_maximum : UInt16?, id: 0x22
      prop reason_string : String?, id: 0x1F
      prop wildcard_subscription_available : Bool?, id: 0x28
      prop subscription_identifier_available : Bool?, id: 0x29
      prop shared_subscription_available : Bool?, id: 0x2A
      prop server_keep_alive : UInt16?, id: 0x13
      prop response_information : String?, id: 0x1A
      prop server_reference : String?, id: 0x1C
      prop authentication_method : String?, id: 0x15
      prop authentication_data : Bytes?, id: 0x16
      prop user_properties : Array(StringPair)?, id: 0x26
    end

    struct PublishProperties
      include Properties

      prop payload_format_indicator : Bool?, id: 0x01
      prop message_expiry_interval : UInt32?, id: 0x02
      # 3.3.2.3.4: a Topic Alias of 0 is a Protocol Error.
      prop topic_alias : UInt16?, id: 0x23, range: 1..65535
      prop response_topic : String?, id: 0x08
      prop correlation_data : Bytes?, id: 0x09
      prop content_type : String?, id: 0x03
      prop user_properties : Array(StringPair)?, id: 0x26
      # 3.3.2.3.8: the one repeatable property besides User Property. The range
      # is 1..268,435,455; 0 is a Protocol Error (stated for SUBSCRIBE in
      # 3.8.2.1.2), and the VBI reader bounds the upper end.
      prop subscription_identifiers : Array(VarInt)?, id: 0x0B, range: 1..268435455
    end

    struct SubscribeProperties
      include Properties

      # 3.8.2.1.2: 0 is a Protocol Error; the VBI reader bounds the upper end.
      # Not repeatable here - a SUBSCRIBE carries at most one.
      prop subscription_identifier : VarInt?, id: 0x0B, range: 1..268435455
      prop user_properties : Array(StringPair)?, id: 0x26
    end

    struct DisconnectProperties
      include Properties

      prop session_expiry_interval : UInt32?, id: 0x11
      prop reason_string : String?, id: 0x1F
      prop server_reference : String?, id: 0x1C
      prop user_properties : Array(StringPair)?, id: 0x26
    end

    struct AuthProperties
      include Properties

      prop authentication_method : String?, id: 0x15
      prop authentication_data : Bytes?, id: 0x16
      prop reason_string : String?, id: 0x1F
      prop user_properties : Array(StringPair)?, id: 0x26
    end

    # Ack-packet properties: Reason String + User Property (3.4.2.2, 3.9.2.1,
    # 3.11.2.1). One struct serves all six ack packets; the aliases keep the
    # per-packet names in the public API.
    struct AckProperties
      include Properties

      prop reason_string : String?, id: 0x1F
      prop user_properties : Array(StringPair)?, id: 0x26
    end

    alias PubAckProperties = AckProperties
    alias SubAckProperties = AckProperties
    alias UnsubAckProperties = AckProperties

    # Unsubscribe carries only User Property (3.10.2.1).
    struct UnsubscribeProperties
      include Properties

      prop user_properties : Array(StringPair)?, id: 0x26
    end
  end
end
