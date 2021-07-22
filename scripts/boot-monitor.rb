#!/bin/env ruby

require 'pp'
require 'io/console'
require 'digest/crc32'
require 'optparse'

CMD_SOF  = '>'
CMD_VERS = 'V'
CMD_SEND = 'S'
CMD_DATA = 'D'
CMD_AUTH = 'U'
CMD_EXEC = 'E'
CMD_STRAP= 'O'
CMD_OTPD = 'P'
CMD_OTPR = 'R'
CMD_OTPC = 'M'
CMD_CONT = 'C'
CMD_ACK  = 'a'
CMD_NACK = 'n'

def read_resp(fd)
    buf = ""
    bin = false
    while (fd.read(1) != CMD_SOF)
    end
    while (c = fd.read(1))
        if c == '#' || c == '%'
            bin = (c == '%')
            break
        end
        buf += c
    end
    items = buf.split(",")
    obj = nil
    if items.length == 3
        obj = {:cmd => items[0],
               :arg => items[1].hex,
               :len => items[2].hex }
        len = items[2].hex
        if bin
            payload = fd.read(len)
            obj[:payload] = payload
            obj[:rawdata] = buf + '%' + payload
        else
            payload = fd.read(len*2)
            obj[:payload] = [payload].pack('H*')
            obj[:rawdata] = buf + '#' + payload
        end
        obj[:crc] = fd.read(8).downcase
        obj[:calccrc] = Digest::CRC32c.hexdigest(obj[:rawdata])
    end
    STDERR.puts "RSP '#{buf}' => #{obj}"
    return obj
end

def fmt_req(cmd, arg = 0, payload = nil)
    buf = sprintf("%c", cmd)
    buf += sprintf(",%08x", arg)
    bin = $options[:binary] ? '%' : '#'
    buf += sprintf(",%08x%c", !payload.nil? ? payload.length : 0, bin)
    if (!payload.nil?)
        if $options[:binary]
            buf += payload
        else
            buf += payload.unpack('H*').first
        end
    end
    return CMD_SOF + buf + Digest::CRC32c.hexdigest(buf)
end

def fmt_otp_data(offset, data)
    odata = [data].pack('H*')
    e = (offset.to_i(16) + odata.length)
    raise "OTP data extends capacity #{e}" if e > 8192
    return fmt_req(CMD_OTPD, offset, odata)
end

def fmt_otp_rand(offset, len)
    e = (offset.to_i(16) + len.to_i(16))
    raise "OTP data extends capacity #{e}" if e > 8192
    return fmt_req(CMD_OTPR, offset, [len.to_i(16)].pack('N'))
end

def do_cmd(cmd)
    STDOUT.write cmd
    STDERR.puts "REQ '#{cmd}'"
    return read_resp(STDIN)
end

def show_examples(title, pdus)
    puts title
    pdus.each_with_index do|p, ix|
        printf "%s: %s\n", (ix & 1) == 0 ? "REQ" : "RSP", p
    end
end

STDIN.sync = true
STDOUT.sync = true
STDERR.reopen("/var/tmp/bootstrap.txt", "w")

$options = {}
OptionParser.new do |opts|
    opts.banner = "Usage: boot-monitor.rb [options]"
    opts.version = 0.1

    opts.on("-b", "--binary", "Send payload in binary form") do
        $options[:binary] = true
    end

    opts.on("-v", "--version", "Do version command exchange") do
        do_cmd(fmt_req(CMD_VERS))
    end

    opts.on("-s", "--send <file>", "Send file") do |file|
        sz = File.size?(file)
        if sz
            rsp = do_cmd(fmt_req(CMD_SEND,sz))
            if rsp[:cmd] != CMD_ACK
                break
            end
            off = 0
            open(file, "r") do |io|
                while rsp[:cmd] == CMD_ACK
                    data = io.read(128)
                    if data && data.length
                        rsp = do_cmd(fmt_req(CMD_DATA,off,data))
                        if rsp[:cmd] != CMD_ACK
                            break
                        end
                        off += data.length
                    else
                        break
                    end
                end
            end
        end
    end

    opts.on("-e", "--execute", "Do execute command") do
        rsp = do_cmd(fmt_req(CMD_EXEC))
    end

    opts.on("-c", "--continue", "Do continue command") do
        rsp = do_cmd(fmt_req(CMD_CONT))
    end

    opts.on("-s", "--strapping <num>", "Do strapping command") do |num|
        rsp = do_cmd(fmt_req(CMD_STRAP,num.to_i))
    end

    opts.on("-o", "--otp-data <offset>:<hexstring>", "Program OTP at offset <offset> with <hexstring> ") do |arg|
        a = arg.split(":")
        raise "Need OTP args as offset:data" unless a.length == 2
        rsp = do_cmd(fmt_otp_data(a[0], a[1]))
    end

    opts.on("-r", "--otp-random <offset>:<length>", "Program OTP at offset <offset> with <length> random data") do |arg|
        a = arg.split(":")
        raise "Need OTP args as offset:length" unless a.length == 2
        rsp = do_cmd(fmt_otp_rand(a[0], a[1]))
    end

    opts.on("-m", "--otp-commit", "Program OTP with current emulation data") do
        rsp = do_cmd(fmt_req(CMD_OTPC))
    end

    opts.on("-x", "--examples", "Show protocol example encodings") do
        show_examples("Get Version", [
                          fmt_req(CMD_VERS),
                          fmt_req(CMD_ACK,0,"Version 1.3 Manic Mantis")
                      ])
        show_examples("Download code", [
                          fmt_req(CMD_SEND,16),
                          fmt_req(CMD_ACK,),
                          fmt_req(CMD_DATA,0,"01284567"),
                          fmt_req(CMD_ACK,0),
                          fmt_req(CMD_DATA,8,"89abcdef"),
                          fmt_req(CMD_ACK,8)
                      ])
        show_examples("Authenticate", [
                          fmt_req(CMD_AUTH,0,"The quick brown fox jumps over the lazy dog"),
                          fmt_req(CMD_ACK)
                      ])
        show_examples("Execute", [
                          fmt_req(CMD_EXEC),
                          fmt_req(CMD_ACK)
                      ])
        show_examples("Override strapping", [
                          fmt_req(CMD_STRAP,10),
                          fmt_req(CMD_ACK)
                      ])
        show_examples("Continue Boot", [
                          fmt_req(CMD_CONT),
                          fmt_req(CMD_NACK)
                      ])
    end

end.order!