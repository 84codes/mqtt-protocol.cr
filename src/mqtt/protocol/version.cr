module MQTT
  module Protocol
    # Shard release version (set from `shards version`).
    VERSION = {{ `shards version`.stringify }}

    # Protocol version negotiated on a connection. The enum value is the
    # protocol level byte sent in CONNECT; the in-memory representation is the
    # concrete `IO::V3` / `IO::V5` type (one per connection), whose framing
    # hooks decide whether a v5 properties section / reason-code byte is present.
    #
    # Enums are Comparable by value, so guards can read `version >= V5`.
    enum Version : UInt8
      V3_1   = 3 # MQIsdp
      V3_1_1 = 4 # MQTT
      V5     = 5 # MQTT

      # Wire protocol name carried in CONNECT for this version.
      def protocol_name : String
        v3_1? ? "MQIsdp" : "MQTT"
      end

      # Inverse of `protocol_name` plus the protocol level byte: the CONNECT
      # variable header (3.1.2.1, 3.1.2.2) is the only place a connection
      # announces its version. MQIsdp/3 is MQTT 3.1, MQTT/4 is 3.1.1, MQTT/5
      # is 5.0; any other pair is an unacceptable protocol version
      # ([MQTT-3.1.2-1], [MQTT-3.1.2-2]).
      def self.from_protocol(name : String, level : UInt8) : Version
        case {name, level}
        when {"MQTT", 0x04u8}   then V3_1_1
        when {"MQTT", 0x05u8}   then V5
        when {"MQIsdp", 0x03u8} then V3_1
        else
          raise Error::UnacceptableProtocolVersion.new("invalid protocol: #{name.inspect} level #{level}")
        end
      end

      # Bytes a properties section contributes to a packet's size: its full
      # wire size in v5, nothing in v3 (no section on the wire). Lets the
      # arithmetic remaining_length(version) methods avoid branching on v5
      # themselves - the one place the rule lives.
      def properties_bytesize(properties) : Int32
        v5? ? properties.bytesize : 0
      end
    end
  end
end
