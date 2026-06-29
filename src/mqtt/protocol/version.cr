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
