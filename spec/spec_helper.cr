require "spec"
require "base64"
require "openssl"
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

# Encode a CBOR text string.
def cbor_tstr(text : String) : Bytes
  io = IO::Memory.new
  bytes = text.to_slice
  raise "cbor_tstr helper only handles short strings" if bytes.size >= 24
  io.write_byte((3_u8 << 5) | bytes.size.to_u8)
  io.write(bytes)
  io.to_slice
end

def sha256(bytes : Bytes) : Bytes
  digest = OpenSSL::Digest.new("SHA256")
  digest.update(bytes)
  digest.final
end

# Assemble authenticator data the way an authenticator would (WebAuthn §6.1).
#
# `credential_id` and `cose_key` are supplied together for a registration; an
# assertion leaves both out and the AT flag stays clear.
def build_authenticator_data(rp_id : String, *, flags : UInt8, sign_count : UInt32 = 0_u32,
                             credential_id : Bytes? = nil, cose_key : Bytes? = nil,
                             aaguid : Bytes? = nil, extensions : Bytes? = nil,
                             rp_id_hash : Bytes? = nil) : Bytes
  io = IO::Memory.new
  io.write(rp_id_hash || sha256(rp_id.to_slice))
  io.write_byte(flags)
  4.times { |i| io.write_byte(((sign_count >> ((3 - i) * 8)) & 0xff).to_u8) }

  if credential_id && cose_key
    io.write(aaguid || Bytes.new(16))
    io.write_byte(((credential_id.size >> 8) & 0xff).to_u8)
    io.write_byte((credential_id.size & 0xff).to_u8)
    io.write(credential_id)
    io.write(cose_key)
  end

  io.write(extensions) if extensions
  io.to_slice
end

def build_client_data(type : String, challenge : Bytes, origin : String) : Bytes
  encoded = Base64.urlsafe_encode(challenge, padding: false)
  %({"type":"#{type}","challenge":"#{encoded}","origin":"#{origin}","crossOrigin":false}).to_slice
end

# An attestation object with fmt "none" — no claim about the make and model
# of the authenticator, which is what a relying party should be asking for.
def build_attestation_object(auth_data : Bytes, fmt : String = "none",
                             att_stmt : Bytes? = nil) : Bytes
  io = IO::Memory.new
  io.write_byte((5_u8 << 5) | 3_u8)
  io.write(cbor_tstr("fmt")); io.write(cbor_tstr(fmt))
  io.write(cbor_tstr("attStmt")); io.write(att_stmt || Bytes[0xa0])
  io.write(cbor_tstr("authData")); io.write(cbor_bstr(auth_data))
  io.to_slice
end

# Flag combinations, spelled out so the specs read as intent.
FLAG_UP = WebAuthn::AuthenticatorData::FLAG_USER_PRESENT
FLAG_UV = WebAuthn::AuthenticatorData::FLAG_USER_VERIFIED
FLAG_BE = WebAuthn::AuthenticatorData::FLAG_BACKUP_ELIGIBLE
FLAG_BS = WebAuthn::AuthenticatorData::FLAG_BACKUP_STATE
FLAG_AT = WebAuthn::AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
FLAG_ED = WebAuthn::AuthenticatorData::FLAG_EXTENSION_DATA

TEST_RP_ID  = "noalyss.example"
TEST_ORIGIN = "https://client1.noalyss.example"

def test_relying_party(id : String = TEST_RP_ID, origins = [TEST_ORIGIN]) : WebAuthn::RelyingParty
  WebAuthn::RelyingParty.new(id: id, origins: origins)
end

# A whole registration, as a browser would hand it over.
record FakeRegistration,
  attestation_object : Bytes,
  client_data_json : Bytes,
  challenge : Bytes,
  credential_id : Bytes,
  signing_key : Jose::JWK::ECKey | Jose::JWK::RSAKey

def fake_registration(rp : WebAuthn::RelyingParty = test_relying_party, *,
                      flags : UInt8 = FLAG_UP | FLAG_UV | FLAG_AT,
                      sign_count : UInt32 = 0_u32,
                      origin : String = TEST_ORIGIN,
                      challenge : Bytes? = nil,
                      key : (Jose::JWK::ECKey | Jose::JWK::RSAKey)? = nil,
                      credential_id : Bytes? = nil,
                      fmt : String = "none",
                      att_stmt : Bytes? = nil,
                      rp_id_hash : Bytes? = nil) : FakeRegistration
  challenge ||= WebAuthn.generate_challenge
  key ||= Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
  credential_id ||= Random::Secure.random_bytes(32)

  cose = key.is_a?(Jose::JWK::ECKey) ? cose_ec2_key(key.public_key) : cose_rsa_key(key.public_key)
  auth_data = build_authenticator_data(
    rp.id, flags: flags, sign_count: sign_count,
    credential_id: credential_id, cose_key: cose, rp_id_hash: rp_id_hash
  )

  FakeRegistration.new(
    attestation_object: build_attestation_object(auth_data, fmt, att_stmt),
    client_data_json: build_client_data(WebAuthn::ClientData::TYPE_CREATE, challenge, origin),
    challenge: challenge,
    credential_id: credential_id,
    signing_key: key
  )
end

record FakeAssertion,
  authenticator_data : Bytes,
  client_data_json : Bytes,
  signature : Bytes,
  challenge : Bytes

def fake_assertion(rp : WebAuthn::RelyingParty, key : Jose::JWK::ECKey | Jose::JWK::RSAKey, *,
                   flags : UInt8 = FLAG_UP | FLAG_UV,
                   sign_count : UInt32 = 1_u32,
                   origin : String = TEST_ORIGIN,
                   challenge : Bytes? = nil,
                   rp_id_hash : Bytes? = nil,
                   tamper_signature : Bool = false) : FakeAssertion
  challenge ||= WebAuthn.generate_challenge
  auth_data = build_authenticator_data(rp.id, flags: flags, sign_count: sign_count, rp_id_hash: rp_id_hash)
  client_data_json = build_client_data(WebAuthn::ClientData::TYPE_GET, challenge, origin)

  signed = IO::Memory.new
  signed.write(auth_data)
  signed.write(sha256(client_data_json))

  signature = authenticator_sign(key, signed.to_slice)
  signature = authenticator_sign(key, "something else".to_slice) if tamper_signature

  FakeAssertion.new(auth_data, client_data_json, signature, challenge)
end
