require 'openssl'

module R509
  module ASN1
    module Generate
      def self.from_string(str)
        value, _ = parse_segment(str)
        value
      end

      def self.to_string(value)
        modifier = modifier_of(value)
        value_str = case value
                    when OpenSSL::ASN1::Sequence
                      inner = value.value.map {|elem| to_string(elem)}.join(';')
                      "SEQ:(#{inner})"
                    when OpenSSL::ASN1::Set
                      inner = value.value.map {|elem| to_string(elem)}.join(';')
                      "SET:(#{inner})"
                    else
                      "#{type_name_of(value)}:#{value.value.to_s}"
                    end
        if modifier.empty?
          value_str
        else
          "#{modifier},#{value_str}"
        end
      end

      def self.to_conf(value)
        modifier = modifier_of(value)
        value_str, conf = case value
                          when OpenSSL::ASN1::Sequence, OpenSSL::ASN1::Set
                            type = value.is_a?(OpenSSL::ASN1::Sequence) ? 'SEQ' : 'SET'
                            conf_name = OpenSSL::Random.random_bytes(16).unpack("H*")[0]
                            conf_str = "[#{conf_name}]\n"
                            confs = ''
                            value.value.each_with_index do |elem, i|
                              elem_str, elem_conf = to_conf(elem)
                              conf_str << "elem_#{i}=#{elem_str}\n"
                              confs << elem_conf
                            end
                            ["#{type}:#{conf_name}", conf_str + confs]
                          else
                            ["#{type_name_of(value)}:#{value.value.to_s}", '']
                          end
        if modifier.empty?
          [value_str, conf]
        else
          ["#{modifier},#{value_str}", conf]
        end
      end

      private

      ESCAPED_STRING_RX = /\A((?:\\.|[^;)])*)(?:[;)]|\z)/.freeze
      TRUE_VALUES = %w(TRUE true YES yes Y y).freeze
      FALSE_VALUES = %w(FALSE false NO no N n).freeze

      def self.modifier_of(value)
        if value.tagging == nil
          ''
        else
          type = value.tagging == :EXPLICIT ? 'EXP' : 'IMP'
          class_letter = case value.tag_class
                         when :UNIVERSAL then 'U'
                         when :APPLICATION then 'A'
                         when :APPLICATION then 'P'
                         when :CONTEXT_SPECIFIC then ''
                         end
          "#{type}:#{value.tag}#{class_letter}"
        end
      end

      def self.type_name_of(value)
        case value
        when OpenSSL::ASN1::GeneralString then 'GeneralString'
        when OpenSSL::ASN1::UTF8String then 'UTF8'
        else value.class.name.split('::').last.upcase
        end
      end

      def self.extract_sequence_segment(str)
        if str[0] != '('
          str
        else
          index = 1
          level = 1
          escaped = false
          while index < str.length && level > 0
            c = str[index]
            if escaped
              escaped = false
            elsif c == '\\'
              escaped = true
            elsif c == '('
              level += 1
            elsif c ==')'
              level -= 1
            end
            index += 1
          end
          if str[index].nil?
            [str[1..-1], '']
          else
            [str[1..(index - 2)], str[(str[index] == ';' || str[index] == ')' ? index + 1 : index)..-1]]
          end
        end
      end

      def self.make_primitive_constructor(modifier_str)
        case modifier_str
        when nil
          Proc.new do |class_name, value|
            ::OpenSSL::ASN1.send(class_name, value)
          end

        when /\A(IMP|EXP)(?:LICIT)?:(\d+)([UAPC]?)\z?/
          tagging = $1 == 'EXP' ? :EXPLICIT : :IMPLICIT
          tag = $2.to_i
          tag_class = tag_class_from_letter($3)
          Proc.new do |class_name, value|
            ::OpenSSL::ASN1.send(class_name, value, tag, tagging, tag_class)
          end

        else
          raise R509::R509Error, "Unrecognized modifier, #{modifier_str}"
        end
      end

      def self.parse_sequence_value(value_str)
        result = []
        seq_str, rest = extract_sequence_segment(value_str)

        while seq_str != ''
          value, seq_str = parse_segment(seq_str)
          result << value
        end

        [result, rest]
      end

      def self.parse_segment(str)
        case str
        when /\A((?:IMP|EXP)(?:LICIT)?:\d+[UAPC]?,)?(.*)\z/
          modifier_str = $1
          type_and_value_str = $2
        else
          raise R509::R509Error, "Unable to parse segment #{str}"
        end
        type, escaped_value_str = type_and_value_str.split(':', 2)
        construct = make_primitive_constructor(modifier_str)
        value_str, rest = extract_primitive_string(escaped_value_str)

        value = case type
                when 'BOOLEAN', 'BOOL'                   then construct[:Boolean, parse_boolean(value_str)]
                when 'NULL'                              then construct[:Null, nil]
                when 'INTEGER', 'INT'                    then construct[:Integer, value_str.to_i]
                when 'ENUMERATED', 'ENUM'                then construct[:Enumerated, value_str.to_i]
                when 'OBJECT', 'OID'                     then construct[:ObjectId, value_str]
                when 'UTCTIME', 'UTC'                    then construct[:UTCTime, parse_utctime(value_str)]
                when 'GENERALIZEDTIME', 'GENTIME'        then construct[:GeneralizedTime, parse_generalizedtime(value_str)]
                when 'OCTETSTRING', 'OCT'                then construct[:OctetString, value_str]
                when 'BITSTRING', 'BITSTR'               then construct[:BitString, value_str]
                when 'UNIVERSALSTRING', 'UNIV'           then construct[:UniversalString, value_str]
                when 'IA5STRING', 'IA5'                  then construct[:IA5String, value_str]
                when 'UTF8String', 'UTF8'                then construct[:UTF8String, value_str]
                when 'BMPSTRING', 'BMP'                  then construct[:BMPString, value_str]
                when 'VISIBLESTRING', 'VISIBLE'          then construct[:ISO64String, value_str]
                when 'PRINTABLESTRING', 'PRINTABLE'      then construct[:PrintableString, value_str]
                when 'T61STRING', 'T61', 'TELETEXSTRING' then construct[:T61String, value_str]
                when 'GeneralString'                     then construct[:GeneralString, value_str]
                when 'NUMERICSTRING', 'NUMERIC'          then construct[:NumericString, value_str]

                when 'SEQUENCE', 'SEQ'
                  seq_value, rest = parse_sequence_value(escaped_value_str)
                  construct[:Sequence, seq_value]

                when 'SET'
                  seq_value, rest = parse_sequence_value(escaped_value_str)
                  construct[:Set, seq_value]

                else
                  raise "Unrecognized type specifier, #{type}"
                end

        [value, rest]
      end

      def self.tag_class_from_letter(letter)
        case letter
        when '', 'C' then :CONTEXT_SPECIFIC
        when 'U'      then :UNIVERSAL
        when 'A'      then :APPLICATION
        when 'P'      then :PRIVATE
        else raise "Unrecognized tag class specifier '#{letter}'"
        end
      end

      def self.parse_boolean(str)
        if TRUE_VALUES.include?(str)
          true
        elsif FALSE_VALUES.include?(str)
          false
        else
          raise "Invalid BOOLEAN value, '#{str}'"
        end
      end

      def self.parse_utctime(str)
        DateTime.strptime(str, '%y%m%d%H%M%S%z').to_time
      end

      def self.parse_generalizedtime(str)
        DateTime.strptime(str, '%Y%m%d%H%M%S%z').to_time
      end

      def self.unescape_string(str)
        (str || '')
            .gsub('\;', ';')
            .gsub('\)', ')')
      end

      def self.extract_primitive_string(str)
        if m = ESCAPED_STRING_RX.match(str)
          [unescape_string(m[1]), str[m.end(0)..-1]]
        else
          ['', '']
        end
      end
    end
  end
end