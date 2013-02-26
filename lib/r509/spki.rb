require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'

module R509
  # class for loading/generating SPKAC/SPKI requests (typically generated by the <keygen> tag
  class Spki
    include R509::IOHelpers

    attr_reader :spki, :key
    # @option opts [String,OpenSSL::Netscape::SPKI] :spki the spki you want to parse
    # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support). if supplied you do not need to pass an spki.
    # @option opts [String] :message_digest Optional digest. sha1, sha224, sha256, sha384, sha512, md5. Defaults to sha1. Only used if you supply a :key and no :spki
    def initialize(opts={})
      if not opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      elsif not opts.has_key?(:spki) and not opts.has_key?(:key)
        raise ArgumentError, 'Must provide either :spki or :key'
      end

      if opts.has_key?(:key)
        if opts[:key].kind_of?(R509::PrivateKey)
          @key = opts[:key]
        else
          @key = R509::PrivateKey.new(:key => opts[:key])
        end
      end
      if opts.has_key?(:spki)
        spki = opts[:spki]
        # first let's try cleaning up the input a bit so OpenSSL is happy with it
        # OpenSSL hates SPKAC=
        spki.sub!("SPKAC=","")
        # it really hates newlines (Firefox loves 'em)
        # so let's normalize line endings
        spki.gsub!(/\r\n?/, "\n")
        # and nuke 'em
        spki.gsub!("\n", "")
        # ...and leading/trailing whitespace
        spki.strip!
        @spki = OpenSSL::Netscape::SPKI.new(spki)
        if not @key.nil? and not @spki.verify(@key.public_key) then
          raise R509Error, 'Key does not match SPKI.'
        end
      end
      # create the SPKI from the private key if it wasn't passed in
      if @spki.nil?
        @spki = OpenSSL::Netscape::SPKI.new
        @spki.public_key = @key.public_key
        if @key.dsa?
          #only DSS1 is acceptable for DSA signing in OpenSSL < 1.0
          #post-1.0 you can sign with anything, but let's be conservative
          #see: http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/PKey/DSA.html
          message_digest = R509::MessageDigest.new('dss1')
        elsif opts.has_key?(:message_digest)
          message_digest = R509::MessageDigest.new(opts[:message_digest])
        else
          message_digest = R509::MessageDigest.new('sha1')
        end
        @spki.sign(@key.key,message_digest.digest)
      end
    end

    # @return [OpenSSL::PKey::RSA] public key
    def public_key
      @spki.public_key
    end

    # Verifies the integrity of the signature on the SPKI
    # @return [Boolean]
    def verify_signature
      @spki.verify(public_key)
    end

    # Converts the SPKI into the PEM format
    #
    # @return [String] the SPKI converted into PEM format.
    def to_pem
      @spki.to_pem
    end

    alias :to_s :to_pem

    # Converts the SPKI into the DER format
    #
    # @return [String] the SPKI converted into DER format.
    def to_der
      @spki.to_der
    end

    # Writes the SPKI into the PEM format
    #
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_pem(filename_or_io)
      write_data(filename_or_io, @spki.to_pem)
    end

    # Writes the SPKI into the DER format
    #
    # @param [String, #write] filename_or_io Either a string of the path for
    #  the file that you'd like to write, or an IO-like object.
    def write_der(filename_or_io)
      write_data(filename_or_io, @spki.to_der)
    end

    # Returns whether the public key is RSA
    #
    # @return [Boolean] true if the public key is RSA, false otherwise
    def rsa?
      @spki.public_key.kind_of?(OpenSSL::PKey::RSA)
    end

    # Returns whether the public key is DSA
    #
    # @return [Boolean] true if the public key is DSA, false otherwise
    def dsa?
      @spki.public_key.kind_of?(OpenSSL::PKey::DSA)
    end

    # Returns whether the public key is EC
    #
    # @return [Boolean] true if the public key is EC, false otherwise
    def ec?
      @spki.public_key.kind_of?(OpenSSL::PKey::EC)
    end

    # Returns the bit strength of the key used to create the SPKI
    # @return [Integer] the integer bit strength.
    def bit_strength
      if self.rsa?
        return @spki.public_key.n.num_bits
      elsif self.dsa?
        return @spki.public_key.p.num_bits
      elsif self.ec?
        raise R509::R509Error, 'Bit strength is not available for EC at this time.'
      end
    end

    # Returns the short name of the elliptic curve used to generate the public key
    # if the key is EC. If not, raises an error.
    #
    # @return [String] elliptic curve name
    def curve_name
      if self.ec?
        @spki.public_key.group.curve_name
      else
        raise R509::R509Error, 'Curve name is only available with EC SPKIs'
      end
    end

    # Returns key algorithm (RSA/DSA)
    #
    # @return [String] value of the key algorithm. RSA or DSA
    def key_algorithm
      if self.rsa?
        :rsa
      elsif self.dsa?
        :dsa
      elsif self.ec?
        :ec
      end
    end
  end
end
