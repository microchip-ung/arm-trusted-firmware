#!/bin/env ruby
# The BL1 binary is controlled by the BL2_AT_EL3 flag
# in plat/microchip/lan966x/lan966x_evb/platform.mk

require 'fileutils'
require 'optparse'

build_envirs            = %I[lan966x_evb lan966x_sr lan966x_b0]
build_types             = %I[debug release]
build_variants          = %I[bl2normal bl2noop]
build_authentifications = %I[noauth auth] # %I[ssk bssk]

build_type_args         = { debug: '--debug', release: '--no-debug' }
build_variant_args      = { bl2normal: '', bl2noop: '-x noop' }
build_auth_args         = { noauth: '--no-tbbr', auth: '--tbbr' }

option = {}
OptionParser.new do |opts|
  opts.banner = %(Usage: #{__FILE__} [options]

  Build all combinations of TF-A artifacts

  Options are:)
  opts.on('-c', '--clean', 'Remove build artifacts') do
    option[:clean] = true
  end
end.order!

def banner(artifacts, cmd)
  5.times { puts }
  puts '#' * 80
  artifacts.each { |_from, to| puts "#{'#' * 5} Artifact: #{to}" unless File.exist?(to) }
  puts "#{'#' * 5} Command: #{cmd}"
  puts '#' * 80
  5.times { puts }
end

def cleanup(do_exit = false)
  files = Dir.glob('*.bin') + Dir.glob('*.fip') + Dir.glob('*.img') + Dir.glob('*.gpt') + Dir.glob('*.dump')
  FileUtils.rm_f(files, verbose: true)
  FileUtils.rm_rf('build', verbose: true)
  exit(0) if do_exit
end

def pre_build
  puts '=' * 80
  puts 'Pre build cleanup'
  cleanup
  puts '=' * 80
end

cleanup(true) if option[:clean]

pre_build
build_envirs.each do |be|
  build_types.each do |bt|
    build_variants.each do |bv|
      next if bv == :bl2noop && (be != :lan966x_b0 || bt != :release) # NOOP builds must be b0 release
      build_authentifications.each do |ba|
        next if ba == :auth && be == :lan966x_evb # EVB does not support authentication of images
        artifacts = [
          ["build/#{be}/#{bt}/bl1.bin",      "#{be}-#{bt}-bl1.bin"],
          ["build/#{be}/#{bt}/fip.bin",      "#{be}-#{bt}-#{bv}-#{ba}.fip"],
          ["build/#{be}/#{bt}/fip.gpt",      "#{be}-#{bt}-#{bv}-#{ba}.gpt"],
          ["build/#{be}/#{bt}/#{be}.img",    "#{be}-#{bt}-#{bv}-#{ba}.img"],
          ["build/#{be}/#{bt}/bl1/bl1.dump", "#{be}-#{bt}-#{bv}-#{ba}-bl1.dump"],
          ["build/#{be}/#{bt}/bl2/bl2.dump", "#{be}-#{bt}-#{bv}-#{ba}-bl2.dump"]
        ]
        cargs = "#{build_type_args[bt]} --gptimg --norimg #{build_auth_args[ba]} -p #{be} #{build_variant_args[bv]}"
        cmd = "ruby scripts/build.rb #{cargs}"
        cmd_clean = 'ruby scripts/build.rb distclean'
        banner(artifacts, cmd)
        system(cmd_clean)
        system(cmd)
        artifacts.each do |from, to|
          FileUtils.mv(from, to, verbose: true) if !File.exist?(to) && File.exist?(from)
        end
      end
    end
  end
end
#  vim: set ts=4 sw=2 sts=2 tw=120 et cc=120 ft=ruby :