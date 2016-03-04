#!/usr/bin/env ruby

require "packetfu"
require "pp"
require "pry"
require "json"

#packets = PacketFu::PcapPackets.new.read(File.read('2016-01-22_A-01_2nd_E2EO.snoop'))
packets = PacketFu::PcapPackets.new.read(File.read(ARGV[0]))
count = 0
packets.each do |pkt|
  count = count + 1
  if PacketFu::TCPPacket.can_parse?(pkt.data)
    tcp_packet = PacketFu::TCPPacket.parse(pkt.data)
    body = tcp_packet.payload

    if body.match(/Req_\d*/) or body.match(/Seq_\d*/)

      print count
      print","

      print Time.at(pkt.timestamp.sec.to_i, pkt.timestamp.usec.to_i).strftime("%F %T.%6N")
      print","

      case tcp_packet.ip_saddr
      when "172.30.48.155"
        case tcp_packet.ip_daddr
        when "172.30.48.140"
          print "E2EO#1 -> NWRO#1"
        when "172.30.48.141"
          print "E2EO#1 -> NWRO#2"
        else
          print "不明IP:#{tcp_packet.ip_daddr}"
        end
      when "172.30.48.156"
        case tcp_packet.ip_daddr
        when "172.30.48.140"
          print "E2EO#2 -> NWRO#1"
        when "172.30.48.141"
          print "E2EO#2 -> NWRO#2"
        else
          print "不明IP:#{tcp_packet.ip_daddr}"
        end
      when "172.30.48.140"
        case tcp_packet.ip_daddr
        when "172.30.48.155"
          print "E2EO#1 <- NWRO#1"
        when "172.30.48.156"
          print "E2EO#2 <- NWRO#1"
        else
          print "不明IP:#{tcp_packet.ip_daddr}"
        end
      when "172.30.48.141"
        case tcp_packet.ip_daddr
        when "172.30.48.155"
          print "E2EO#1 <- NWRO#2"
        when "172.30.48.156"
          print "E2EO#2 <- NWRO#2"
        else
          print "不明IP:#{tcp_packet.ip_daddr}"
        end
      else
        print "不明IP:#{tcp_packet.ip_saddr}"
      end
      print ","

      #binding.pry
      case body
      when %r{HTTP/1.1\s(\d\d\d\s.*)\r}
        print $1
      when %r{DELETE\s}
        print "NSR削除要求"
      when %r{asyncNotificationLocation}
        case body
        when %r{resource.*?v1/vnfds\"}
          print "カタログ(VNFD)登録要求"
        when %r{resource.*?v1/nsds\"}
          print "カタログ(NSD)登録要求"
        when %r{resource.*?v1/nsrs/reservations\"}
          print "NSR予約要求"
        when %r{resource.*?v1/nsrs\"}
          print "NSR生成要求"
        when %r{resource.*?v1/nsrs/nwro_nsr}
          print "NSR変更要求"
        when %r{resource.*?v1/vlrs/reservations\"}
          print "VLR生成予約要求"
        when %r{resource.*?v1/vlrs\"}
          print "VLR生成要求"
        when %r{resource.*?v1/vlrs/nwro_vlr_.*/reservations\"}
          print "VLR変更予約要求"
        when %r{resource.*?v1/vlrs/nwro_vlr_}
          print "VLR変更要求"
        else
          print "電文識別不能!"
        end
      when %r{createLocation}
        #binding.pry
        case body
        when %r{resource.*?v1\\/vnfds}
          print "カタログ(VNFD)登録完了通知"
        when %r{resource.*?v1\\/nsds}
          print "カタログ(NSD)登録完了通知"
        when %r{resource.*?v1/nsrs/reservations}
          print "NSR予約完了通知"
        when %r{resource.*?v1/nsrs\"}
          print "NSR生成完了通知"
        when %r{resource.*?v1/nsrs/nwro_nsr}
          print "NSR変更完了通知"
        when %r{resource.*?v1/vlrs/reservations\"}
          print "VLR生成予約完了通知"
        when %r{resource.*?v1/vlrs\"}
          print "VLR生成完了通知"
        when %r{resource.*?v1/vlrs/nwro_vlr_.*/reservations\"}
          print "VLR変更予約完了通知"
        when %r{resource.*?v1/vlrs/nwro_vlr_}
          print "VLR変更完了通知"
        else
          print "電文識別不能!"
        end
      when %r{resource.*?v1/nsrs/nwro_nsr}
        print "NSR削除完了通知"
      else
        print "電文識別不能!"
      end
      print ","

      print body.match(/Req_\d*/)
      print ","
      print body.match(/Seq_\d*/)

      #binding.pry
      if %r{resultCode\":\"(\d{8,8})\"} =~ body
        if $1 == "00000000"
          print ",OK"
        else
          print ",NG:#{$1}"
        end
      end
      print "\n"
    end
  end
end

