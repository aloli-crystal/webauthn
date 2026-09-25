require "spec"
require "../src/webauthn"

# Build CBOR by hand, so the decoder is tested against bytes rather than
# against its own encoder — this shard has no encoder, and should not grow
# one just to make testing convenient.
def cbor_bytes(*parts : Int32 | UInt8 | Bytes | String) : Bytes
  io = IO::Memory.new
  parts.each do |part|
    case part
    in Int32  then io.write_byte(part.to_u8)
    in UInt8  then io.write_byte(part)
    in Bytes  then io.write(part)
    in String then io.write(part.to_slice)
    end
  end
  io.to_slice
end

# Encode a CBOR unsigned or negative integer.
def cbor_int(value : Int) : Bytes
  io = IO::Memory.new
  major, n = value < 0 ? {1_u8, (-1 - value).to_u64} : {0_u8, value.to_u64}
  case n
  when .< 24          then io.write_byte((major << 5) | n.to_u8)
  when .<= UInt8::MAX then io.write_byte((major << 5) | 24_u8); io.write_byte(n.to_u8)
  when .<= UInt16::MAX
    io.write_byte((major << 5) | 25_u8)
    io.write_byte((n >> 8).to_u8)
    io.write_byte((n & 0xff).to_u8)
  else
    io.write_byte((major << 5) | 26_u8)
    4.times { |i| io.write_byte(((n >> ((3 - i) * 8)) & 0xff).to_u8) }
  end
  io.to_slice
end

# Encode a CBOR byte string.
def cbor_bstr(bytes : Bytes) : Bytes
  io = IO::Memory.new
  n = bytes.size
  case n
  when .< 24          then io.write_byte((2_u8 << 5) | n.to_u8)
  when .<= UInt8::MAX then io.write_byte((2_u8 << 5) | 24_u8); io.write_byte(n.to_u8)
  else
    io.write_byte((2_u8 << 5) | 25_u8)
    io.write_byte((n >> 8).to_u8)
    io.write_byte((n & 0xff).to_u8)
  end
  io.write(bytes)
  io.to_slice
end

# Encode a CBOR map from already-encoded key/value byte pairs.
def cbor_map(pairs : Array(Tuple(Bytes, Bytes))) : Bytes
  io = IO::Memory.new
  raise "cbor_map helper only handles small maps" if pairs.size >= 24
  io.write_byte((5_u8 << 5) | pairs.size.to_u8)
  pairs.each { |(k, v)| io.write(k); io.write(v) }
  io.to_slice
end

# A COSE_Key for an EC2 (elliptic curve) public key.
def cose_ec2_key(key : Jose::JWK::ECKey, alg : Int64 = WebAuthn::COSE::ALG_ES256,
                 crv : Int64 = 1_i64) : Bytes
  cbor_map([
    {cbor_int(WebAuthn::COSE::LABEL_KTY), cbor_int(WebAuthn::COSE::KTY_EC2)},
    {cbor_int(WebAuthn::COSE::LABEL_ALG), cbor_int(alg)},
    {cbor_int(WebAuthn::COSE::LABEL_EC2_CRV), cbor_int(crv)},
    {cbor_int(WebAuthn::COSE::LABEL_EC2_X), cbor_bstr(key.x)},
    {cbor_int(WebAuthn::COSE::LABEL_EC2_Y), cbor_bstr(key.y)},
  ])
end

# A COSE_Key for an RSA public key.
def cose_rsa_key(key : Jose::JWK::RSAKey, alg : Int64 = WebAuthn::COSE::ALG_RS256) : Bytes
  cbor_map([
    {cbor_int(WebAuthn::COSE::LABEL_KTY), cbor_int(WebAuthn::COSE::KTY_RSA)},
    {cbor_int(WebAuthn::COSE::LABEL_ALG), cbor_int(alg)},
    {cbor_int(WebAuthn::COSE::LABEL_RSA_N), cbor_bstr(key.n)},
    {cbor_int(WebAuthn::COSE::LABEL_RSA_E), cbor_bstr(key.e)},
  ])
end

# Sign the way an authenticator does: over the bare bytes, with no JOSE
# envelope. ECDSA comes back as ASN.1 DER, RSA as a raw octet string — which
# is exactly what a CTAP authenticator emits.
def authenticator_sign(key : Jose::JWK::ECKey | Jose::JWK::RSAKey, data : Bytes,
                       algorithm : Jose::JWS::Algorithm? = nil) : Bytes
  algorithm ||= key.is_a?(Jose::JWK::ECKey) ? Jose::JWS::Algorithm::ES256 : Jose::JWS::Algorithm::RS256
  Jose::JWS.sign_data(data, algorithm, key)
end
