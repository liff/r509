require 'spec_helper'
require 'r509/other_name'
require 'openssl'

describe R509::ASN1::Generate do
  describe '#from_string' do
    it "parses a BOOLEAN" do
      %w(BOOL BOOLEAN).each do |type_syntax|
        %w(TRUE true YES yes Y y).each do |value_syntax|
          expect(subject.from_string("#{type_syntax}:#{value_syntax}")).to der_eq(OpenSSL::ASN1::Boolean.new(true))
        end
        %w(FALSE false NO no N n).each do |value_syntax|
          expect(subject.from_string("#{type_syntax}:#{value_syntax}")).to der_eq(OpenSSL::ASN1::Boolean.new(false))
        end
      end
    end

    it "parses a NULL" do
      expect(subject.from_string('NULL')).to der_eq(OpenSSL::ASN1::Null.new(nil))
    end

    it "parses an INTEGER" do
      %w(INTEGER:3 INT:3).each do |syntax|
        expect(subject.from_string(syntax)).to der_eq(OpenSSL::ASN1::Integer.new(3))
      end
    end

    it "parses an ENUMERATED" do
      %w(ENUMERATED:4 ENUM:4).each do |syntax|
        expect(subject.from_string(syntax)).to der_eq(OpenSSL::ASN1::Enumerated.new(4))
      end
    end

    it "parses an OBJECT" do
      %w(OBJECT:1.2.3.4 OID:1.2.3.4).each do |syntax|
        expect(subject.from_string(syntax)).to der_eq(OpenSSL::ASN1::ObjectId.new("1.2.3.4"))
      end
    end

    it "parses a UTCTIME" do
      expect(subject.from_string('UTC:010203040506Z')).to der_eq(OpenSSL::ASN1::UTCTime.new(Time.utc(2001, 2, 3, 4, 5, 6)))
    end

    it "parses a GENERALIZEDTIME" do
      expect(subject.from_string('GENTIME:20010203040506Z')).to der_eq(OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2001, 2, 3, 4, 5, 6)))
    end

    it "parses an OCTETSTRING" do
      expect(subject.from_string('OCT:hello world')).to der_eq(OpenSSL::ASN1::OctetString.new("hello world"))
    end

    it "parses an OCTETSTRING with an escaped semicolon" do
      expect(subject.from_string('OCT:hello \;world')).to der_eq(OpenSSL::ASN1::OctetString.new("hello ;world"))
    end

    it "parses an OCTETSTRING with an escaped closing paren" do
      expect(subject.from_string('OCT:hello \)world')).to der_eq(OpenSSL::ASN1::OctetString.new("hello )world"))
    end

    it "parses a simple SEQUENCE" do
      e1 = OpenSSL::ASN1::Boolean.new(true)
      e2 = OpenSSL::ASN1::Integer.new(3)
      expect(subject.from_string('SEQ:(BOOL:yes;INT:3)')).to der_eq(::OpenSSL::ASN1::Sequence.new([e1, e2]))
    end

    it "parses a SEQUENCE with an embedded string element" do
      e1 = OpenSSL::ASN1::Boolean.new(true)
      e2 = OpenSSL::ASN1::OctetString.new("hi there")
      e3 = OpenSSL::ASN1::Integer.new(3)

      expect(subject.from_string('SEQ:(BOOL:yes;OCT:hi there;INT:3)')).to der_eq(::OpenSSL::ASN1::Sequence.new([e1, e2, e3]))
    end

    it "parses a SEQUENCE with an embedded string element with an escaped semicolon" do
      e1 = OpenSSL::ASN1::Boolean.new(true)
      e2 = OpenSSL::ASN1::OctetString.new("hi ;there")
      e3 = OpenSSL::ASN1::Integer.new(3)

      expect(subject.from_string('SEQ:(BOOL:yes;OCT:hi \;there;INT:3)')).to der_eq(::OpenSSL::ASN1::Sequence.new([e1, e2, e3]))
    end

    it "parses a SEQUENCE with an embedded string element with an escaped paren" do
      e1 = OpenSSL::ASN1::Boolean.new(true)
      e2 = OpenSSL::ASN1::OctetString.new("hi )there")
      e3 = OpenSSL::ASN1::Integer.new(3)

      expect(subject.from_string('SEQ:(BOOL:yes;OCT:hi \)there;INT:3)')).to der_eq(::OpenSSL::ASN1::Sequence.new([e1, e2, e3]))
    end

    it "parses a nested SEQUENCE" do
      p1 = OpenSSL::ASN1::Boolean.new(true)
      p2 = OpenSSL::ASN1::Integer.new(3)
      p3 = OpenSSL::ASN1::Integer.new(4)
      p4 = OpenSSL::ASN1::Boolean.new(false)
      p5 = OpenSSL::ASN1::OctetString.new('duh')
      p6 = OpenSSL::ASN1::Integer.new(5)

      s3 = OpenSSL::ASN1::Sequence.new([p4, p5])
      s2 = OpenSSL::ASN1::Sequence.new([p2, p3, s3])
      s1 = OpenSSL::ASN1::Sequence.new([p1, s2, p6])

      expect(subject.from_string('SEQ:(BOOL:yes;SEQ:(INT:3;INT:4;SEQ:(BOOL:no;OCT:duh));INT:5)')).to der_eq(s1)
    end

    it "parses a SET" do
      e1 = OpenSSL::ASN1::Boolean.new(true)
      e2 = OpenSSL::ASN1::Integer.new(3)
      expect(subject.from_string('SET:(BOOL:yes;INT:3)')).to der_eq(OpenSSL::ASN1::Set.new([e1, e2]))
    end

    it "parses PKINIT" do
      str = 'SEQ:(EXP:0,GeneralString:REALM;EXP:1,SEQ:(EXP:0,INTEGER:1;EXP:1,SEQ:(GeneralString:krbtgt;GeneralString:REALM)))'
      struct = subject.from_string(str)
      result = subject.to_string(struct)
      expect(result).to eq(str)
    end
  end
end
