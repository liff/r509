require 'simplecov'
SimpleCov.start
begin
  require 'coveralls'
  Coveralls.wear!
rescue LoadError
end

$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
$LOAD_PATH.unshift File.expand_path("../", __FILE__)
require 'rubygems'
require 'fixtures'
require 'rspec'
require 'r509'

# exclude EC specific tests if it's unsupported
unless R509.ec_supported?
  puts "\e[#{31}mWARNING: NOT RUNNING EC TESTS BECAUSE EC IS UNSUPPORTED ON YOUR RUBY INSTALLATION\e[0m"
  R509.print_debug
  RSpec.configure do |c|
    c.filter_run_excluding :ec => true
  end
end

RSpec.configure do |config|
  config.alias_it_should_behave_like_to :it_validates, "it validates"
end

RSpec::Matchers.define :der_eq do |expected|
  match do |actual|
    actual.to_der == expected.to_der
  end
end