require 'openssl'
require 'r509/exceptions'
require 'r509/io_helpers'
require 'r509/helpers'

module R509
  # class for loading/generating SPKAC/SPKI requests (typically generated by the <keygen> tag
  class SPKI
    include R509::IOHelpers
    include R509::Helpers

    attr_reader :spki, :key
    # @option opts [String,OpenSSL::Netscape::SPKI] :spki the spki you want to parse
    # @option opts [R509::PrivateKey,String] :key optional private key to supply. either an unencrypted PEM/DER string or an R509::PrivateKey object (use the latter if you need password/hardware support). if supplied you do not need to pass an spki.
    # @option opts [String] :message_digest Optional digest. sha1, sha224, sha256, sha384, sha512, md5. Defaults to sha1. Only used if you supply a :key and no :spki
    def initialize(opts={})
      if not opts.kind_of?(Hash)
        raise ArgumentError, 'Must provide a hash of options'
      elsif not opts.key?(:spki) and not opts.key?(:key)
        raise ArgumentError, 'Must provide either :spki or :key'
      end

      @key = load_private_key(opts)

      if opts.key?(:spki)
        @spki = parse_spki(opts[:spki])
      else
      # create the SPKI from the private key if it wasn't passed in
        @spki = build_spki(opts[:message_digest])
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

    alias_method :to_s, :to_pem

    # Returns the signature algorithm (e.g., RSA-SHA1, ecdsa-with-SHA256)
    #
    # @return [String] signature algorithm string
    def signature_algorithm
      data = OpenSSL::ASN1.decode(self.to_der)
      return data.entries[1].value.entries[0].value
    end

    private

    # Tries to clean and parse an inbound SPKI
    # @param [String] spki string
    # @return [OpenSSL::Netscape::SPKI] spki object
    def parse_spki(spki)
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
      spki = OpenSSL::Netscape::SPKI.new(spki)
      if not @key.nil? and not spki.verify(@key.public_key) then
        raise R509Error, 'Key does not match SPKI.'
      end
      return spki
    end

    # Tries to build an SPKI using an existing private key
    # @param [String] md optional message digest
    # @return [OpenSSL::Netscape::SPKI] spki object
    def build_spki(md)
      spki = OpenSSL::Netscape::SPKI.new
      spki.public_key = @key.public_key
      if @key.dsa?
        # only DSS1 is acceptable for DSA signing in OpenSSL < 1.0
        # post-1.0 you can sign with anything, but let's be conservative
        # see: http://www.ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/PKey/DSA.html
        message_digest = R509::MessageDigest.new('dss1')
      else
        message_digest = R509::MessageDigest.new(md)
      end
      spki.sign(@key.key,message_digest.digest)
      return spki
    end

    # Returns the proper instance variable
    alias_method :internal_obj, :spki
  end
end
