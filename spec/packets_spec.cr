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
      describe "#from_io" do
        it "validates protocol name" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length 10u8
          io.write_string "FOOO"
          mio.rewind

          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid protocol/) do
            connect = MQTT::Protocol::Packet.from_io(mio)
          end
        end

        it "validates protocol name length" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b00010000u8 # connect
          io.write_remaining_length 10u8
          io.write_string "to long"
          mio.rewind

          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid protocol length/) do
            connect = MQTT::Protocol::Packet.from_io(mio)
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
            connect = MQTT::Protocol::Packet.from_io(mio)
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

          connect.should be_a MQTT::Protocol::Connect
          connect = connect.as MQTT::Protocol::Connect
          connect.client_id.should eq "foobar"
          connect.keepalive.should eq 60
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
            will: MQTT::Protocol::Will.new(wtopic, "will body".to_slice, 1u8, false)
          )

          connect.to_io(io)
          mio.rewind

          parsed_connect = MQTT::Protocol::Packet.from_io(io).as MQTT::Protocol::Connect

          parsed_connect.username.should eq username
          parsed_connect.password.should eq password
          parsed_connect.will.not_nil!.topic.should eq wtopic
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

          connect.should be_a MQTT::Protocol::Connack
          connect = connect.as MQTT::Protocol::Connack
          connect.session_present?.should be_true
          connect.return_code.value.should eq 0u8
        end
      end

      describe "#to_io" do
        it "can write" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)

          connack = MQTT::Protocol::Connack.new(false, MQTT::Protocol::Connack::ReturnCode::Accepted)
          connack.to_io(io)

          mio.rewind

          parsed_connack = MQTT::Protocol::Packet.from_io(io).as MQTT::Protocol::Connack

          parsed_connack.return_code.should eq MQTT::Protocol::Connack::ReturnCode::Accepted
          parsed_connack.session_present?.should be_false
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

          publish.should be_a MQTT::Protocol::Publish
          publish = publish.as MQTT::Protocol::Publish
          publish.topic.should eq topic
          publish.body.should eq payload
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

          parsed_publish = MQTT::Protocol::Packet.from_io(io).as MQTT::Protocol::Publish

          parsed_publish.topic.should eq topic
          parsed_publish.body.should eq payload
          parsed_publish.packet_id.not_nil!.should eq packet_id
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
          unsubscribe.should be_a MQTT::Protocol::Unsubscribe
          unsubscribe = unsubscribe.as(MQTT::Protocol::Unsubscribe)
          unsubscribe.packet_id.should eq 50u16
          unsubscribe.topics.first.should eq "MyTopic"
        end

        it "handles multiple topics" do
          topics = ["MyTopic", "MyTopic2", "MyTopic4", "MyTopic3"]
          length = 0
          topics.each do |t|
            length += 2 + t.bytesize
          end
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10100010u8           # Unsubscribe
          io.write_remaining_length 2 + length # 2 for variable header, rest is length
          io.write_int(50u16)
          topics.each do |t|
            io.write_string(t)
          end
          mio.rewind

          unsubscribe = MQTT::Protocol::Packet.from_io(mio)
          unsubscribe.should be_a MQTT::Protocol::Unsubscribe
          unsubscribe = unsubscribe.as(MQTT::Protocol::Unsubscribe)
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
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid flags/) do
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

          parsed_packet = MQTT::Protocol::Packet.from_io(io)
          parsed_packet.should be_a MQTT::Protocol::Unsubscribe
          unsubscribe_packet = parsed_packet.as(MQTT::Protocol::Unsubscribe)
          unsubscribe_packet.packet_id.should eq 65u16
          unsubscribe_packet.topics.each_with_index do |topic, index|
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

          unsub_ack = MQTT::Protocol::Packet.from_io(mio)
          unsub_ack.should be_a MQTT::Protocol::UnsubAck
          unsub_ack.as(MQTT::Protocol::UnsubAck).packet_id.should eq 50u16
        end

        it "raises if flags are set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b10110010u8 # UnsubAck
          io.write_remaining_length 2
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid flags/) do
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

          unsub_ack = MQTT::Protocol::UnsubAck.new(65534u16)
          unsub_ack.to_io(io)

          mio.rewind

          parsed_packet = MQTT::Protocol::Packet.from_io(io)
          parsed_packet.should be_a MQTT::Protocol::UnsubAck
          parsed_packet.as(MQTT::Protocol::UnsubAck).packet_id.should eq 65534u16
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

          ping_req = MQTT::Protocol::Packet.from_io(mio)
          ping_req.should be_a MQTT::Protocol::PingReq
        end
        it "raises if flags are set" do
          mio = IO::Memory.new
          io = MQTT::Protocol::IO.new(mio)
          io.write_byte 0b11000010u8  # PingReq
          io.write_remaining_length 0 # always 0
          mio.rewind
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid flags/) do
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

          ping_req = MQTT::Protocol::PingReq.new
          ping_req.to_io(io)

          mio.rewind

          parsed_packet = MQTT::Protocol::Packet.from_io(io)
          parsed_packet.should be_a MQTT::Protocol::PingReq
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
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid flags/) do
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

          ping_req = MQTT::Protocol::PingResp.new
          ping_req.to_io(io)

          mio.rewind

          parsed_packet = MQTT::Protocol::Packet.from_io(io)
          parsed_packet.should be_a MQTT::Protocol::PingResp
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
          expect_raises(MQTT::Protocol::Error::PacketDecode, /invalid flags/) do
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

          parsed_packet = MQTT::Protocol::Packet.from_io(io)
          parsed_packet.should be_a MQTT::Protocol::Disconnect
        end
      end
    end
  end
end
