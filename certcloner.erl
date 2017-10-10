-module(certcloner).
-export([clone/3]).

-include_lib("public_key/include/public_key.hrl").

clone(CertPemFileName, KeyPemFileName, DerOutFileName) ->
	{ok, PemBin} = file:read_file(CertPemFileName),
	[{'Certificate', DER, not_encrypted} | _] = public_key:pem_decode(PemBin),
	{ok, KPemBin} = file:read_file(KeyPemFileName),
	[{'RSAPrivateKey' = T, RSA, not_encrypted} | _] = public_key:pem_decode(KPemBin),
	Key = public_key:der_decode(T, RSA),
	Cert = public_key:pkix_decode_cert(DER, otp),
	#'RSAPrivateKey'{modulus = Mod, publicExponent = Exp} = Key,
	NewLeafCertSPKI = Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo#'OTPSubjectPublicKeyInfo'{subjectPublicKey = #'RSAPublicKey'{modulus = Mod, publicExponent = Exp}},
	NewLeafCert = Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'{subjectPublicKeyInfo = NewLeafCertSPKI},
	NewDER = public_key:pkix_sign(NewLeafCert, Key),
	file:write_file(DerOutFileName, NewDER).
