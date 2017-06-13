require "openssl"
require "r509/asn1/generate"

module R509
  class OtherName
    attr_accessor :oid, :value

    def initialize(arg)
      case arg
      when R509::OtherName
        @oid = arg.oid
        @value = arg.value
      when String
        @oid, @value = self.class.parse(arg)
      when Array
        @oid = arg[0]
        @value = arg[1]
      else
        raise ArgumentError, "Cannot create OtherName from #{arg}"
      end
    end

    def to_s
      "otherName:#{@oid};#{R509::ASN1::Generate.to_string(@value)}"
    end

    private

    FORMAT_RX = /\AotherName:([0-9.]+);(.*)\z/.freeze

    def self.parse(str)
      if m = FORMAT_RX.match(str)
        [m[1], R509::ASN1::Generate.from_string(m[2])]
      else
        raise ArgumentError, "'#{str}' is not a valid otherName string"
      end
    end
  end
end