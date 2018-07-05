-module(certcloner).
-export([clone/3, clone/4]).

-include_lib("public_key/include/public_key.hrl").

clone(CertPemFileName, KeyPemFileName, DerOutFileName) ->
	{ok, PemBin} = file:read_file(CertPemFileName),
	[{'Certificate', DER, not_encrypted} | _] = public_key:pem_decode(PemBin),
	{ok, KPemBin} = file:read_file(KeyPemFileName),
	[{'RSAPrivateKey' = T, RSA, not_encrypted} | _] = public_key:pem_decode(KPemBin),
	Key = public_key:der_decode(T, RSA),
	Cert = public_key:pkix_decode_cert(DER, otp),
	#'RSAPrivateKey'{modulus = Mod, publicExponent = Exp} = Key,
	NewLeafCertSPKI = Cert#'OTPCertificate'.tbsCertificate
		#'OTPTBSCertificate'.subjectPublicKeyInfo
		#'OTPSubjectPublicKeyInfo'{
		   subjectPublicKey = #'RSAPublicKey'{modulus = Mod, publicExponent = Exp}},
	NewLeafCert = Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'{
		subjectPublicKeyInfo = NewLeafCertSPKI},
	file:write_file(DerOutFileName, public_key:pkix_sign(NewLeafCert, Key)).

clone(CertPemFileName, IssuerKeyPemFileName, SubjectKeyPemFileName, DerOutFileName) ->
	{ok, PemBin} = file:read_file(CertPemFileName),
	[{'Certificate', DER, not_encrypted} | _] = public_key:pem_decode(PemBin),
	{ok, IKPemBin} = file:read_file(IssuerKeyPemFileName),
	[{'RSAPrivateKey' = IT, IRSA, not_encrypted} | _] = public_key:pem_decode(IKPemBin),
	IssuerKey = public_key:der_decode(IT, IRSA),
	{ok, SKPemBin} = file:read_file(SubjectKeyPemFileName),
	[{'RSAPrivateKey' = ST, SRSA, not_encrypted} | _] = public_key:pem_decode(SKPemBin),
	SubjectKey = public_key:der_decode(ST, SRSA),
	Cert = public_key:pkix_decode_cert(DER, otp),
	#'RSAPrivateKey'{modulus = Mod, publicExponent = Exp} = SubjectKey,
	NewLeafCertSPKI = Cert#'OTPCertificate'.tbsCertificate
		#'OTPTBSCertificate'.subjectPublicKeyInfo
		#'OTPSubjectPublicKeyInfo'{
		   subjectPublicKey = #'RSAPublicKey'{modulus = Mod, publicExponent = Exp}},
	NewLeafCert = Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'{
		subjectPublicKeyInfo = NewLeafCertSPKI},
	file:write_file(DerOutFileName, public_key:pkix_sign(NewLeafCert, IssuerKey)).
