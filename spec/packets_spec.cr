require "./spec_helper"

describe MQTT::Protocol::Packet do
  describe "#from_io" do
    it "should raise error on invalid type" do
      mio = IO::Memory.new
      mio.write_byte 0xF0u8
      mio.write_byte 0u8
      mio.rewind

      io = MQTT::Protocol::IO.new(mio)

      expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid packet type/) do
        MQTT::Protocol::Packet.from_io(io)
      end
    end

    describe "Connect" do
      it "validates flags" do
        mio = IO::Memory.new
        io = MQTT::Protocol::IO.new(mio)
        io.write_byte 0b00010100u8 # connect
        io.write_remaining_length 10u8
        mio.rewind

        expect_raises(MQTT::Protocol::Error::InvalidFlags) do
          MQTT::Protocol::Packet.from_io(mio)
        end
      end

      describe "#from_io" do
        it "validates protocol name" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length 16u8
          io.write_string "FOOO"
          io.write_byte 4u8  # protocol = 4 (3.1.1)
          io.write_byte 0u8  # connect flags
          io.write_int 60u16 # keepalive
          io.write_string "" # empty client_id
          mio.rewind

          expect_raises(MQTT::Protocol::Error::UnacceptableProtocolVersion, /invalid protocol/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "validates protocol name length" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length 18u8
          io.write_string "too long"
          io.write_byte 4u8  # protocol = 4 (3.1.1)
          io.write_byte 0u8  # connect flags
          io.write_int 60u16 # keepalive
          io.write_string "" # empty client_id
          mio.rewind

          expect_raises(MQTT::Protocol::Error::UnacceptableProtocolVersion, /invalid protocol/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "validates protocol version" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length 10u8
          io.write_string "MQTT"
          io.write_byte 5u8
          mio.rewind

          expect_raises(MQTT::Protocol::Error::UnacceptableProtocolVersion) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "client_id is parsed" do
          client_id = "foobar"

          remaining_length = client_id.bytesize + 10

          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length remaining_length.to_u8
          io.write_string "MQTT"
          io.write_byte 4u8  # protocol = 4 (3.1.1)
          io.write_byte 0u8  # Connect flags
          io.write_int 60u16 # keepalive = 60
          io.write_string client_id
          mio.rewind

          connect = MQTT::Protocol::Packet.from_io(mio)

          connect = connect.should be_a MQTT::Protocol::Connect
          connect.client_id.should eq "foobar"
          connect.keepalive.should eq 60
        end

        it "validates the connect flags based on will [MQTT-3.1.2-11]" do
          remaining_length = 10

          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length remaining_length.to_u8
          io.write_string "MQTT"
          io.write_byte 4u8          # protocol = 4 (3.1.1)
          io.write_byte 0b00101000u8 # Connect flags
          io.write_int 60u16         # keepalive = 60
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "validates that the password flag is not set when username flag is no set [MQTT-3.1.2-22]" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length 10u8
          io.write_string "MQTT"
          io.write_byte 4u8          # protocol = 4 (3.1.1)
          io.write_byte 0b01000000u8 # Connect flags
          io.write_int 60u16         # keepalive = 60
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "validates that clean_session is false when empty client_id" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length 10u8
          io.write_string "MQTT"
          io.write_byte 4u8          # protocol = 4 (3.1.1)
          io.write_byte 0b00000000u8 # Connect flags
          io.write_int 60u16         # keepalive = 60
          io.write_string ""
          mio.rewind
          expect_raises(MQTT::Protocol::Error::IdentifierRejected) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          client_id = "client-foo"
          clean_session = false
          keepalive = 60u16
          username = "aaaaaaaa"
          password = "bbbbbbbb".to_slice
          wtopic = "wtopic"

          connect = MQTT::Protocol::Connect.new(
            client_id: client_id,
            clean_session: clean_session,
            keepalive: keepalive,
            username: username,
            password: password,
            will: MQTT::Protocol::Will.new(wtopic, "will payload".to_slice, 1u8, false)
          )

          connect.to_io(io)
          mio.rewind

          connect = MQTT::Protocol::Packet.from_io(io)
          connect = connect.should be_a MQTT::Protocol::Connect
          connect.username.should eq username
          connect.password.should eq password
          connect.will.try(&.topic).should eq wtopic
        end

        it "supports MQTT 3.1 protocol" do
          # Test MQTT 3.1 protocol by directly writing a Connect packet with version 0x03
          # and verifying it's read back correctly
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          # Write packet header
          io.write_byte(0b00010000u8) # Connect packet

          # Build the packet content in a separate IO to calculate length
          content = IO::Memory.new
          content_io = MQTT::Protocol::IO.new(content)
          content_io.write_string("MQIsdp")
          content_io.write_byte(0x03u8)            # MQTT 3.1 version
          content_io.write_byte(0b00000010u8)      # Connect flags - clean session
          content_io.write_int(30u16)              # Keepalive
          content_io.write_string("mqtt31-client") # Client ID

          # Write the remaining length and content
          io.write_remaining_length(content.size)
          io.write_bytes_raw(content.to_slice)

          # Rewind to read
          mio.rewind

          # Read back and verify
          packet = MQTT::Protocol::Packet.from_io(io)
          packet.should be_a MQTT::Protocol::Connect

          # Reset and read again to verify protocol name and version
          mio.rewind
          _header_byte = mio.read_byte      # Skip type/flags
          _remaining_length = mio.read_byte # Skip remaining length

          # Read protocol name
          protocol_len = mio.read_bytes(UInt16, IO::ByteFormat::NetworkEndian)
          protocol_name_bytes = Bytes.new(protocol_len)
          mio.read_fully(protocol_name_bytes)
          protocol_name = String.new(protocol_name_bytes)
          protocol_name.should eq "MQIsdp"

          # Read protocol version
          protocol_version = mio.read_byte
          protocol_version.should eq 0x03
        end
      end
    end

    describe "Will" do
      describe "#initialize" do
        it "does not support wildcard topics" do
          expect_raises(ArgumentError) do
            MQTT::Protocol::Will.new("topic/#", "body".to_slice, 1, false)
          end
        end
      end
    end

    describe "Connack" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00100000u8  # connack
          io.write_remaining_length 2 # always 2
          io.write_byte 0b00000001u8  # connack flags, session present=1
          io.write_byte 0u8           # return code, 0 = Accepted
          mio.rewind

          connect = MQTT::Protocol::Packet.from_io(mio)

          connect = connect.should be_a MQTT::Protocol::Connack
          connect.session_present?.should be_true
          connect.return_code.value.should eq 0u8
        end

        it "validates flags" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00100100u8  # connack
          io.write_remaining_length 2 # always 2
          mio.rewind

          expect_raises(MQTT::Protocol::Error::InvalidFlags) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "validates connack flags" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00100000u8  # connack
          io.write_remaining_length 2 # always 2
          io.write_byte 0b00100001u8  # connack flags, session present=1
          io.write_byte 0u8           # return code, 0 = Accepted
          mio.rewind

          expect_raises(MQTT::Protocol::Error::InvalidConnackFlags) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          connack = MQTT::Protocol::Connack.new(false, MQTT::Protocol::Connack::ReturnCode::Accepted)
          connack.to_io(io)

          mio.rewind

          connack = MQTT::Protocol::Packet.from_io(io)
          connack = connack.should be_a MQTT::Protocol::Connack
          connack.return_code.should eq MQTT::Protocol::Connack::ReturnCode::Accepted
          connack.session_present?.should be_false
        end
      end
    end

    describe "Publish" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          topic = "a/b/c"
          payload = "foobar and barfoo".to_slice
          remaining_length = topic.bytesize + payload.size + 2 # 2 = sizeof topic len

          io.write_byte 0b00110000u8
          io.write_remaining_length remaining_length
          io.write_string topic
          io.write_bytes_raw payload

          mio.rewind

          publish = MQTT::Protocol::Packet.from_io(io)

          publish = publish.should be_a MQTT::Protocol::Publish
          publish.topic.should eq topic
          publish.payload.should eq payload
        end

        it "raises error if dup is set for QoS 0 messages" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          topic = "a/b/c"
          payload = "foobar and barfoo".to_slice
          remaining_length = topic.bytesize + payload.size + 2 # 2 = sizeof topic len

          io.write_byte 0b00111000u8
          io.write_remaining_length remaining_length
          io.write_string topic
          io.write_bytes_raw payload

          mio.rewind

          expect_raises(MQTT::Protocol::Error::PacketDecode) do
            MQTT::Protocol::Packet.from_io(io)
          end
        end

        it "raises PacketDecode if topic contains wildcard" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          topic = "a/+/c"
          payload = "foobar and barfoo".to_slice
          remaining_length = topic.bytesize + payload.size + 2 # 2 = sizeof topic len

          io.write_byte 0b00111000u8
          io.write_remaining_length remaining_length
          io.write_string topic
          io.write_bytes_raw payload

          mio.rewind

          expect_raises(MQTT::Protocol::Error::PacketDecode) do
            MQTT::Protocol::Packet.from_io(io)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          topic = "a/b/c"
          payload = "foobar and barfoo".to_slice
          packet_id = 100u16
          publish = MQTT::Protocol::Publish.new(topic, payload, packet_id, false, 1, false)
          publish.to_io(io)

          mio.rewind

          publish = MQTT::Protocol::Packet.from_io(io)
          publish = publish.should be_a MQTT::Protocol::Publish

          publish.topic.should eq topic
          publish.payload.should eq payload
          publish.packet_id.should eq packet_id
        end

        it "raises error if dup is set for QoS 0 messages" do
          topic = "a/b/c"
          payload = "foobar and barfoo".to_slice
          packet_id = 100u16
          expect_raises(ArgumentError) do
            MQTT::Protocol::Publish.new(topic, payload, packet_id, true, 0, false)
          end
        end

        it "does not raise error when dup is unset for QoS 0 messages" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          topic = "a/b/c"
          payload = "foobar and barfoo".to_slice
          packet_id = 100u16
          publish = MQTT::Protocol::Publish.new(topic, payload, packet_id, false, 0, false)
          publish.to_io(io)
          mio.rewind

          publish = MQTT::Protocol::Packet.from_io(io)
          publish = publish.should be_a MQTT::Protocol::Publish

          publish.topic.should eq topic
          publish.payload.should eq payload
          publish.dup?.should eq false
        end
      end

      describe "#initialize" do
        it "raises an error if QoS is 3" do
          topic = "a/b/c"
          payload = "foobar and barfoo".to_slice
          packet_id = 100u16
          expect_raises(ArgumentError) do
            MQTT::Protocol::Publish.new(topic, payload, packet_id, false, 3, false)
          end
        end

        describe "with wildcard in topic" do
          it "should raise ArguementError" do
            topic = "a/#"
            payload = "foobar and barfoo".to_slice
            packet_id = 100u16

            expect_raises(ArgumentError) do
              MQTT::Protocol::Publish.new(topic, payload, packet_id, false, 1, false)
            end

            topic = "a/+/c"
            expect_raises(ArgumentError) do
              MQTT::Protocol::Publish.new(topic, payload, packet_id, false, 1, false)
            end
          end
        end
      end
    end

    describe "PubAck" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123
          io.write_byte(4u8 << 4)
          io.write_remaining_length 2
          io.write_int packet_id
          mio.rewind

          puback = MQTT::Protocol::Packet.from_io(mio)
          puback = puback.should be_a MQTT::Protocol::PubAck
          puback.packet_id.should eq packet_id
        end
      end
      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123u16
          puback = MQTT::Protocol::PubAck.new(packet_id)
          puback.to_io(io)
          mio.rewind

          puback = MQTT::Protocol::Packet.from_io(io)
          puback = puback.should be_a MQTT::Protocol::PubAck
          puback.packet_id.should eq packet_id
        end
      end
    end

    describe "PubRec" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123
          io.write_byte(5u8 << 4)
          io.write_remaining_length 2
          io.write_int packet_id
          mio.rewind

          pubrec = MQTT::Protocol::Packet.from_io(mio)
          pubrec = pubrec.should be_a MQTT::Protocol::PubRec
          pubrec.packet_id.should eq packet_id
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123u16
          pubrec = MQTT::Protocol::PubRec.new(packet_id)
          pubrec.to_io(io)
          mio.rewind

          pubrec = MQTT::Protocol::Packet.from_io(io)
          pubrec = pubrec.should be_a MQTT::Protocol::PubRec
          pubrec.packet_id.should eq packet_id
        end
      end
    end

    describe "PubRel" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123
          io.write_byte (6u8 << 4) | 2u8
          io.write_remaining_length 2
          io.write_int packet_id
          mio.rewind

          pubrel = MQTT::Protocol::Packet.from_io(mio)
          pubrel = pubrel.should be_a MQTT::Protocol::PubRel
          pubrel.packet_id.should eq packet_id
        end
      end
      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123u16
          pubrel = MQTT::Protocol::PubRel.new(packet_id)
          pubrel.to_io(io)
          mio.rewind

          pubrel = MQTT::Protocol::Packet.from_io(io)
          pubrel = pubrel.should be_a MQTT::Protocol::PubRel
          pubrel.packet_id.should eq packet_id
        end
      end
    end

    describe "PubComp" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123
          io.write_byte (7u8 << 4) | 2u8
          io.write_remaining_length 2
          io.write_int packet_id
          mio.rewind

          pubcomp = MQTT::Protocol::Packet.from_io(mio)
          pubcomp = pubcomp.should be_a MQTT::Protocol::PubComp
          pubcomp.packet_id.should eq packet_id
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          packet_id = 123u16
          pubcomp = MQTT::Protocol::PubComp.new(packet_id)
          pubcomp.to_io(io)
          mio.rewind

          pubcomp = MQTT::Protocol::Packet.from_io(io)
          pubcomp = pubcomp.should be_a MQTT::Protocol::PubComp
          pubcomp.packet_id.should eq packet_id
        end
      end
    end
    describe "Subscribe" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10000010u8 # Subscribe
          # 2 for variable header, 2 for Int32, topic size and qos
          io.write_remaining_length 2 + 2 + "MyTopicFilter".bytesize + 1
          io.write_int(55u16)
          io.write_string("MyTopicFilter")
          io.write_byte(1u8)
          mio.rewind

          subscribe = MQTT::Protocol::Packet.from_io(mio)
          subscribe = subscribe.should be_a MQTT::Protocol::Subscribe
          subscribe.packet_id.should eq 55u16
          subscribe.topic_filters.first.topic.should eq "MyTopicFilter"
          subscribe.topic_filters.first.qos.should eq 1u8
        end

        it "raises if flags are not set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10000000u8 # Subscribe
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid flags/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if length is less than or eq to 2" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10000010u8 # Subscribe
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /protocol violation/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if QoS is > 2" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10000010u8 # Subscribe
          # 2 for variable header, 2 for Int32, topic size and qos
          io.write_remaining_length 2 + 2 + "MyTopicFilter".bytesize + 1
          io.write_int(55u16)
          io.write_string("MyTopicFilter")
          io.write_byte(3u8)
          mio.rewind

          expect_raises(MQTT::Protocol::Error::PacketDecode) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        describe "with multi-level wildcard" do
          it "should not support '#' not in the end" do
            topic = "a/#/b"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind

            expect_raises(MQTT::Protocol::Error::PacketDecode) do
              MQTT::Protocol::Packet.from_io(mio)
            end
          end

          it "should support '#' in the end" do
            topic = "a/#"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind
            subscribe = MQTT::Protocol::Packet.from_io(mio)
            subscribe = subscribe.should be_a MQTT::Protocol::Subscribe
            subscribe.topic_filters.first.topic.should eq topic
          end

          it "should not support '#' on a combined topic level" do
            topic = "a/as#"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind
            expect_raises(MQTT::Protocol::Error::PacketDecode) do
              MQTT::Protocol::Packet.from_io(mio)
            end
          end

          it "should support only '#'" do
            topic = "#"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind
            subscribe = MQTT::Protocol::Packet.from_io(mio)
            subscribe = subscribe.should be_a MQTT::Protocol::Subscribe
            subscribe.topic_filters.first.topic.should eq topic
          end

          it "should not support multiple '#'" do
            topic = "a/#/s/#"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind
            expect_raises(MQTT::Protocol::Error::PacketDecode) do
              MQTT::Protocol::Packet.from_io(mio)
            end
          end
        end

        describe "with single-level wildcard" do
          it "should support '+' not in the end" do
            topic = "a/+/b"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind

            subscribe = MQTT::Protocol::Packet.from_io(mio)
            subscribe = subscribe.should be_a MQTT::Protocol::Subscribe
            subscribe.topic_filters.first.topic.should eq topic
          end

          it "should not support '+' unless covers entire topic level" do
            topic = "a/a+/b"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind

            expect_raises(MQTT::Protocol::Error::PacketDecode) do
              MQTT::Protocol::Packet.from_io(mio)
            end
          end

          it "should support '+' in first level" do
            topic = "+/a/b"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind

            subscribe = MQTT::Protocol::Packet.from_io(mio)
            subscribe = subscribe.should be_a MQTT::Protocol::Subscribe
            subscribe.topic_filters.first.topic.should eq topic
          end

          it "should support '+' in last level" do
            topic = "a/b/+"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind

            subscribe = MQTT::Protocol::Packet.from_io(mio)
            subscribe = subscribe.should be_a MQTT::Protocol::Subscribe
            subscribe.topic_filters.first.topic.should eq topic
          end

          it "should not support a/+b/c+/#" do
            topic = "a/+b/c+/#"
            mio = IO::Memory.new
            io = MQTT::Protocol::IO.new(mio)
            io.write_byte 0b10000010u8 # Subscribe
            # 2 for variable header, 2 for Int32, topic size and qos
            io.write_remaining_length 2 + 2 + topic.bytesize + 1
            io.write_int(55u16)
            io.write_string(topic)
            io.write_byte(1u8)
            mio.rewind

            expect_raises(MQTT::Protocol::Error::PacketDecode) do
              MQTT::Protocol::Packet.from_io(mio)
            end
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          topic_filters = [MQTT::Protocol::Subscribe::TopicFilter.new("My/topic/filter", 0),
                           MQTT::Protocol::Subscribe::TopicFilter.new("My/topic/filter1", 1),
                           MQTT::Protocol::Subscribe::TopicFilter.new("My/topic/filter2", 2)]
          subscribe = MQTT::Protocol::Subscribe.new(topic_filters, 65u16)
          subscribe.to_io(io)

          mio.rewind

          subscribe_packet = MQTT::Protocol::Packet.from_io(io)
          subscribe_packet = subscribe_packet.should be_a MQTT::Protocol::Subscribe
          subscribe_packet.packet_id.should eq 65u16
          subscribe_packet.topic_filters.each_with_index do |topic_filter, index|
            topic_filter.should eq topic_filters[index]
          end
        end

        it "should not allow empty TopicFilters" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          topic_filters = [] of MQTT::Protocol::Subscribe::TopicFilter
          subscribe = MQTT::Protocol::Subscribe.new(topic_filters, 65u16)
          expect_raises(MQTT::Protocol::Error::PacketEncode) do
            subscribe.to_io(io)
          end
        end
      end
    end

    describe "SubAck" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10010000u8      # SubAck
          io.write_remaining_length 2 + 4 # 2 for variable header, 1 for each 4 UInt8
          io.write_int(50u16)
          io.write_byte(0u8)
          io.write_byte(1u8)
          io.write_byte(2u8)
          io.write_byte(128u8)
          mio.rewind

          suback = MQTT::Protocol::Packet.from_io(mio)
          suback = suback.should be_a MQTT::Protocol::SubAck
          suback.packet_id.should eq 50u16
          suback.return_codes[0].should eq MQTT::Protocol::SubAck::ReturnCode::QoS0
          suback.return_codes[1].should eq MQTT::Protocol::SubAck::ReturnCode::QoS1
          suback.return_codes[2].should eq MQTT::Protocol::SubAck::ReturnCode::QoS2
          suback.return_codes[3].should eq MQTT::Protocol::SubAck::ReturnCode::Failure
        end

        it "is has invalid return Code" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10010000u8      # SubAck
          io.write_remaining_length 2 + 1 # 2 for variable header, 1 for each 4 UInt8
          io.write_int(50u16)
          io.write_byte(5u8)
          mio.rewind

          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid return code 5/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if flags are set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10010001u8 # SubAck
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid flags/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if length is less than or eq to 2" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10010000u8 # SubAck
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /protocol violation/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          return_codes = [MQTT::Protocol::SubAck::ReturnCode::QoS0,
                          MQTT::Protocol::SubAck::ReturnCode::QoS1,
                          MQTT::Protocol::SubAck::ReturnCode::QoS2,
                          MQTT::Protocol::SubAck::ReturnCode::Failure]
          suback = MQTT::Protocol::SubAck.new(return_codes, 65u16)
          suback.to_io(io)

          mio.rewind

          suback = MQTT::Protocol::Packet.from_io(io)
          suback = suback.should be_a MQTT::Protocol::SubAck
          suback.packet_id.should eq 65u16
          suback.return_codes.each_with_index do |return_code, index|
            return_code.should eq return_codes[index]
          end
        end
      end
    end

    describe "Unsubscribe" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10100010u8                           # Unsubscribe
          io.write_remaining_length 2 + 2 + "MyTopic".bytesize # 2 for variable header, 2 for Int32
          io.write_int(50u16)
          io.write_string("MyTopic")
          mio.rewind

          unsubscribe = MQTT::Protocol::Packet.from_io(mio)
          unsubscribe = unsubscribe.should be_a MQTT::Protocol::Unsubscribe
          unsubscribe.packet_id.should eq 50u16
          unsubscribe.topics.first.should eq "MyTopic"
        end

        it "handles multiple topics" do
          topics = ["MyTopic", "MyTopic2", "MyTopic4", "MyTopic3"]
          length = 0
          topics.each do |topic|
            length += 2 + topic.bytesize
          end
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10100010u8           # Unsubscribe
          io.write_remaining_length 2 + length # 2 for variable header, rest is length
          io.write_int(50u16)
          topics.each do |topic|
            io.write_string(topic)
          end
          mio.rewind

          unsubscribe = MQTT::Protocol::Packet.from_io(mio)
          unsubscribe = unsubscribe.should be_a MQTT::Protocol::Unsubscribe
          unsubscribe.packet_id.should eq 50u16
          unsubscribe.topics.size.should eq 4
          unsubscribe.topics.each_with_index do |topic, index|
            topic.should eq topics[index]
          end
        end

        it "raises if flags are not set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10100000u8 # Unsubscribe
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::InvalidFlags) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if length is larger than 2" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10100010u8 # Unsubscribe
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /protocol violation/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          topics = ["abc", "def", "ghij"]
          unsubscribe = MQTT::Protocol::Unsubscribe.new(topics, 65u16)
          unsubscribe.to_io(io)

          mio.rewind

          unsubscribe = MQTT::Protocol::Packet.from_io(io)
          unsubscribe = unsubscribe.should be_a MQTT::Protocol::Unsubscribe
          unsubscribe.packet_id.should eq 65u16
          unsubscribe.topics.each_with_index do |topic, index|
            topic.should eq topics[index]
          end
        end
      end
    end

    describe "UnsubAck" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10110000u8  # UnsubAck
          io.write_remaining_length 2 # always 0
          io.write_int(50u16)
          mio.rewind

          unsuback = MQTT::Protocol::Packet.from_io(mio)
          unsuback = unsuback.should be_a MQTT::Protocol::UnsubAck
          unsuback.packet_id.should eq 50u16
        end

        it "raises if flags are set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10110010u8 # UnsubAck
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::InvalidFlags) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if length is not 2" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10110000u8 # UnsubAck
          io.write_remaining_length 0
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid length/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          unsuback = MQTT::Protocol::UnsubAck.new(65534u16)
          unsuback.to_io(io)

          mio.rewind

          unsuback = MQTT::Protocol::Packet.from_io(io)
          unsuback = unsuback.should be_a MQTT::Protocol::UnsubAck
          unsuback.packet_id.should eq 65534u16
        end
      end
    end

    describe "PingReq" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11000000u8  # PingReq
          io.write_remaining_length 0 # always 0
          mio.rewind

          pingreq = MQTT::Protocol::Packet.from_io(mio)
          pingreq.should be_a MQTT::Protocol::PingReq
        end
        it "raises if flags are set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11000010u8  # PingReq
          io.write_remaining_length 0 # always 0
          mio.rewind
          expect_raises(MQTT::Protocol::Error::InvalidFlags) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if length is not 0" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11000000u8 # PingReq
          io.write_remaining_length 1
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid length/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          pingreq = MQTT::Protocol::PingReq.new
          pingreq.to_io(io)

          mio.rewind

          pingreq = MQTT::Protocol::Packet.from_io(io)
          pingreq.should be_a MQTT::Protocol::PingReq
        end
      end
    end

    describe "PingResp" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11010000u8  # PingResp
          io.write_remaining_length 0 # always 0
          mio.rewind

          ping_req = MQTT::Protocol::Packet.from_io(mio)
          ping_req.should be_a MQTT::Protocol::PingResp
        end
        it "raises if flags are set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11010010u8  # PingResp
          io.write_remaining_length 0 # always 0
          mio.rewind
          expect_raises(MQTT::Protocol::Error::InvalidFlags) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if length is not 0" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11010000u8 # PingResp
          io.write_remaining_length 1
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid length/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          pingresp = MQTT::Protocol::PingResp.new
          pingresp.to_io(io)

          mio.rewind

          pingresp = MQTT::Protocol::Packet.from_io(io)
          pingresp.should be_a MQTT::Protocol::PingResp
        end
      end
    end

    describe "Disconnect" do
      describe "#from_io" do
        it "is parsed" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11100000u8  # Disconnect
          io.write_remaining_length 0 # always 0
          mio.rewind

          disconnect = MQTT::Protocol::Packet.from_io(mio)
          disconnect.should be_a MQTT::Protocol::Disconnect
        end

        it "raises if flags are set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11100100u8  # Disconnect
          io.write_remaining_length 0 # always 0
          mio.rewind
          expect_raises(MQTT::Protocol::Error::InvalidFlags) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "raises if length is not 0" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11100000u8 # Disconnect
          io.write_remaining_length 1
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid length/) do
            MQTT::Protocol::Packet.from_io(mio)
          end
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          disconnect = MQTT::Protocol::Disconnect.new
          disconnect.to_io(io)

          mio.rewind

          disconnect = MQTT::Protocol::Packet.from_io(io)
          disconnect.should be_a MQTT::Protocol::Disconnect
        end
      end
    end
  end
end
