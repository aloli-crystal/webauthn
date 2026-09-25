module WebAuthn
  # Minimal CBOR decoder (RFC 8949), scoped to what WebAuthn needs.
  #
  # Two structures arrive as CBOR: the attestation object produced at
  # registration, and the COSE key inside it. Neither uses tags, indefinite
  # lengths, floats or simple values beyond `true` / `false` / `null`, so
  # those are rejected rather than half-supported.
  #
  # Decoding is deliberately strict. This parses attacker-reachable input:
  # anything malformed, truncated or over-long must be refused outright, not
  # coaxed into a plausible value.
  module CBOR
    class Error < Exception
    end

    class MalformedError < Error
    end

    class UnsupportedError < Error
    end

    # Nesting depth beyond which input is refused, so a hostile payload
    # cannot exhaust the stack.
    MAX_DEPTH = 32

    # Map keys are `Int64` or `String`, the only two kinds WebAuthn uses:
    # COSE keys are keyed by (mostly negative) integers, the attestation
    # object by short strings.
    alias Key = Int64 | String

    # A decoded CBOR value.
    #
    # Nesting goes through this struct rather than a recursive alias: an alias
    # that refers to itself expands differently at each mention, so
    # `Hash(Key, Value)` written by a caller is not the same type as the one
    # inside the union. A named type sidesteps that, and gives callers the
    # `JSON::Any`-style accessors they would otherwise write by hand.
    struct Any
      alias Type = (Bool | Int64 | String | Bytes | Array(Any) | Hash(Key, Any))?

      getter raw : Type

      def initialize(@raw : Type)
      end

      def ==(other : Any) : Bool
        raw == other.raw
      end

      def ==(other) : Bool
        raw == other
      end

      def hash(hasher)
        raw.hash(hasher)
      end

      def inspect(io : IO) : Nil
        raw.inspect(io)
      end

      def to_s(io : IO) : Nil
        raw.to_s(io)
      end

      # `nil?` is a pseudo-method in Crystal and cannot be redefined.
      def null? : Bool
        raw.nil?
      end

      {% for name, type in {i: Int64, s: String, bytes: Bytes, bool: Bool} %}
        def as_{{ name.id }}? : {{ type }}?
          raw.as?({{ type }})
        end

        # Tested against nil rather than truthiness: `false` is a perfectly
        # good Bool, and `value || raise` would reject it.
        def as_{{ name.id }} : {{ type }}
          value = raw.as?({{ type }})
          raise TypeError.new("expected {{ type }}, got #{raw.class}") if value.nil?
          value
        end
      {% end %}

      def as_a? : Array(Any)?
        raw.as?(Array(Any))
      end

      def as_a : Array(Any)
        as_a? || raise TypeError.new("expected an array, got #{raw.class}")
      end

      def as_h? : Hash(Key, Any)?
        raw.as?(Hash(Key, Any))
      end

      def as_h : Hash(Key, Any)
        as_h? || raise TypeError.new("expected a map, got #{raw.class}")
      end

      # Look up a map entry, raising when absent.
      #
      # Absence is checked with `has_key?`, not truthiness: an entry whose
      # value is `false` or CBOR null is present.
      def [](key : Key) : Any
        map = as_h?
        raise TypeError.new("expected a map, got #{raw.class}") if map.nil?
        raise TypeError.new("missing CBOR map key #{key.inspect}") unless map.has_key?(key)
        map[key]
      end

      def []?(key : Key) : Any?
        as_h?.try(&.[key]?)
      end

      def has_key?(key : Key) : Bool
        !!as_h?.try(&.has_key?(key))
      end
    end

    # Raised when a decoded value is not of the shape the caller required.
    class TypeError < Error
    end

    # Decode exactly one CBOR item, refusing trailing bytes.
    def self.decode(bytes : Bytes) : Any
      decoder = Decoder.new(bytes)
      value = decoder.read_value
      unless decoder.at_end?
        raise MalformedError.new("#{decoder.remaining} trailing byte(s) after the CBOR item")
      end
      value
    end

    # Decode one CBOR item and report how many bytes it consumed.
    #
    # The attestation object embeds `authData` as a byte string whose contents
    # are parsed separately, so the caller sometimes needs the boundary.
    def self.decode_first(bytes : Bytes) : {value: Any, size: Int32}
      decoder = Decoder.new(bytes)
      value = decoder.read_value
      {value: value, size: decoder.position}
    end

    # Decode and require a map at the top level.
    def self.decode_map(bytes : Bytes) : Hash(Key, Any)
      decode(bytes).as_h? || raise MalformedError.new("expected a CBOR map at the top level")
    end

    # :nodoc:
    class Decoder
      MAJOR_UNSIGNED = 0_u8
      MAJOR_NEGATIVE = 1_u8
      MAJOR_BYTES    = 2_u8
      MAJOR_TEXT     = 3_u8
      MAJOR_ARRAY    = 4_u8
      MAJOR_MAP      = 5_u8
      MAJOR_TAG      = 6_u8
      MAJOR_SIMPLE   = 7_u8

      getter position : Int32

      def initialize(@bytes : Bytes)
        @position = 0
      end

      def at_end? : Bool
        @position >= @bytes.size
      end

      def remaining : Int32
        @bytes.size - @position
      end

      def read_value(depth : Int32 = 0) : Any
        Any.new(read_raw(depth))
      end

      private def read_raw(depth : Int32) : Any::Type
        raise MalformedError.new("CBOR nesting deeper than #{MAX_DEPTH}") if depth > MAX_DEPTH

        initial = read_byte
        major = initial >> 5
        additional = initial & 0x1f

        case major
        when MAJOR_UNSIGNED
          read_argument(additional).to_i64
        when MAJOR_NEGATIVE
          # -1 - n, per RFC 8949 §3.1.
          n = read_argument(additional)
          raise UnsupportedError.new("negative integer out of Int64 range") if n > Int64::MAX.to_u64
          -1_i64 - n.to_i64
        when MAJOR_BYTES
          read_bytes(read_length(additional))
        when MAJOR_TEXT
          read_text(read_length(additional))
        when MAJOR_ARRAY
          count = read_length(additional)
          array = Array(Any).new(Math.min(count, 64))
          count.times { array << Any.new(read_raw(depth + 1)) }
          array
        when MAJOR_MAP
          read_map(read_length(additional), depth)
        when MAJOR_TAG
          raise UnsupportedError.new("CBOR tags are not supported")
        when MAJOR_SIMPLE
          read_simple(additional)
        else
          raise MalformedError.new("unreachable CBOR major type #{major}")
        end
      end

      # Only the three simple values CBOR gives a name to. Floats and the
      # remaining simple values are refused rather than guessed at.
      private def read_simple(additional : UInt8) : Bool?
        case additional
        when 20 then false
        when 21 then true
        when 22 then nil
        else
          raise UnsupportedError.new("unsupported CBOR simple value or float (additional info #{additional})")
        end
      end

      private def read_text(count : Int32) : String
        text = String.new(read_bytes(count))
        raise MalformedError.new("text string is not valid UTF-8") unless text.valid_encoding?
        text
      end

      private def read_map(count : Int32, depth : Int32) : Hash(Key, Any)
        map = Hash(Key, Any).new(initial_capacity: Math.min(count, 64))
        count.times do
          key = read_raw(depth + 1)
          unless key.is_a?(Int64) || key.is_a?(String)
            raise UnsupportedError.new("CBOR map keys must be integers or text strings")
          end
          # A duplicate key is not a quirk to tolerate: it lets an attacker
          # show one value to a parser and another to the next.
          raise MalformedError.new("duplicate CBOR map key #{key.inspect}") if map.has_key?(key)
          map[key] = Any.new(read_raw(depth + 1))
        end
        map
      end

      # Read the argument that follows the initial byte (RFC 8949 §3).
      private def read_argument(additional : UInt8) : UInt64
        case additional
        when .< 24
          additional.to_u64
        when 24
          read_byte.to_u64
        when 25
          read_uint(2)
        when 26
          read_uint(4)
        when 27
          read_uint(8)
        when 31
          raise UnsupportedError.new("indefinite-length CBOR items are not supported")
        else
          raise MalformedError.new("reserved CBOR additional information #{additional}")
        end
      end

      # Lengths are bounded by what is actually left in the buffer, so a
      # declared length of 2^32 cannot make us try to allocate it.
      private def read_length(additional : UInt8) : Int32
        value = read_argument(additional)
        if value > remaining.to_u64
          raise MalformedError.new("CBOR item declares a length of #{value} with only #{remaining} byte(s) left")
        end
        value.to_i32
      end

      private def read_uint(count : Int32) : UInt64
        ensure_available(count)
        result = 0_u64
        count.times do
          result = (result << 8) | @bytes[@position].to_u64
          @position += 1
        end
        result
      end

      private def read_byte : UInt8
        ensure_available(1)
        byte = @bytes[@position]
        @position += 1
        byte
      end

      private def read_bytes(count : Int32) : Bytes
        ensure_available(count)
        slice = @bytes[@position, count].dup
        @position += count
        slice
      end

      private def ensure_available(count : Int32) : Nil
        return if remaining >= count
        raise MalformedError.new("truncated CBOR: needed #{count} byte(s), #{remaining} left")
      end
    end
  end
end
