#!/usr/bin/env bash
# Generates the TLS test fixtures used by the unit and instrumented tests of the tls package.
# Requires OpenSSL 3.4+ (for -not_before/-not_after) and keytool (JDK). Run from any directory:
#   ./generate.sh
# The generated files are committed, re-run only when fixtures need to change.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
EXTRAS_ONLY=0
[ "${1:-}" = "--extras-only" ] && EXTRAS_ONLY=1
rm -rf out && mkdir -p out
cd out

# --- Extra fixtures (inspired by jellyfin-desktop tests/test_certificates.cpp) -------------------------------------
# Own CA, only used for import tests. Regenerate only these with: ./generate.sh --extras-only
extras() {
	cd "$HERE"
	rm -rf out-extra && mkdir -p out-extra && cd out-extra
	local pass="jellyfin" utf8_pass="Pässwörd!123_üöä€" days=7300
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout extra-ca.key -out extra-ca.pem -days $days \
		-subj "/CN=Extra Fixture CA/O=Jellyfin TLS Fixtures" -addext "basicConstraints=critical,CA:true" 2>/dev/null

	extra_cert() { # name, subject, keygen args...
		local name=$1 subject=$2; shift 2
		openssl genpkey "$@" -out "$name.key" 2>/dev/null
		openssl req -new -utf8 -key "$name.key" -out "$name.csr" -subj "$subject" 2>/dev/null
		openssl x509 -req -in "$name.csr" -CA extra-ca.pem -CAkey extra-ca.key -CAcreateserial -out "$name.pem" -days $days \
			-extfile <(printf "basicConstraints=CA:false\nextendedKeyUsage=clientAuth") 2>/dev/null
	}
	extra_p12() { # output, name, password, extra args...
		local out=$1 name=$2 password=$3; shift 3
		openssl pkcs12 -export -inkey "$name.key" -in "$name.pem" -certfile extra-ca.pem -out "../client/$out" \
			-passout "pass:$password" -name client "$@"
	}
	local tdes=(-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1)

	# Key types
	extra_cert ec256 "/CN=extra-ec256/O=Jellyfin TLS Fixtures" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
	extra_cert rsa8192 "/CN=extra-rsa8192/O=Jellyfin TLS Fixtures" -algorithm RSA -pkeyopt rsa_keygen_bits:8192
	extra_cert brainpool256 "/CN=extra-brainpool256/O=Jellyfin TLS Fixtures" -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1
	openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsa.param 2>/dev/null
	extra_cert dsa2048 "/CN=extra-dsa2048/O=Jellyfin TLS Fixtures" -paramfile dsa.param
	extra_p12 extra-rsa8192-3des.p12 rsa8192 "$pass" "${tdes[@]}"
	extra_p12 extra-brainpool256-3des.p12 brainpool256 "$pass" "${tdes[@]}"
	extra_p12 extra-dsa2048-3des.p12 dsa2048 "$pass" "${tdes[@]}"
	# Post-quantum signature key (needs OpenSSL 3.5): no TLS stack of Android offers ML-DSA, rejected at import
	extra_cert mldsa65 "/CN=extra-mldsa65/O=Jellyfin TLS Fixtures" -algorithm ML-DSA-65
	extra_p12 extra-mldsa65-3des.p12 mldsa65 "$pass" "${tdes[@]}"

	# Encryption and integrity variants (EC P-256 key)
	extra_p12 extra-ec256-aes128.p12 ec256 "$pass" -certpbe AES-128-CBC -keypbe AES-128-CBC
	extra_p12 extra-ec256-mac-sha512.p12 ec256 "$pass" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha512
	extra_p12 extra-ec256-mac-sha384.p12 ec256 "$pass" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha384
	extra_p12 extra-ec256-pbes1-md5.p12 ec256 "$pass" -legacy -certpbe PBE-MD5-DES -keypbe PBE-MD5-DES -macalg md5
	extra_p12 extra-ec256-utf8-password.p12 ec256 "$utf8_pass" "${tdes[@]}"

	# Subjects: UTF-8 and without CN
	extra_cert utf8 "/CN=Тестовый клиент ü€/O=Jellyfin Тест" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
	extra_cert nocn "/O=Jellyfin TLS Fixtures/OU=No Common Name" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
	extra_p12 extra-utf8-subject-3des.p12 utf8 "$pass" "${tdes[@]}"
	extra_p12 extra-no-cn-3des.p12 nocn "$pass" "${tdes[@]}"

	# CA formats: bag attributes (openssl pkcs12 -nokeys output), bundle with comments
	openssl pkcs12 -export -nokeys -in extra-ca.pem -out ca-only.p12 -passout "pass:$pass" -certpbe PBE-SHA1-3DES 2>/dev/null
	openssl pkcs12 -in ca-only.p12 -nokeys -passin "pass:$pass" -out ../ca/extra-bag-attributes.pem 2>/dev/null
	{ echo "# Jellyfin TLS fixtures: CA bundle with comments"; echo "# Extra Fixture CA"; cat extra-ca.pem
	  echo; echo "# Second certificate"; cat ec256.pem; } > ../ca/extra-bundle-comments.pem
	extra_cert expiredclient "/CN=extra-expired/O=Jellyfin TLS Fixtures" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
	openssl x509 -req -in expiredclient.csr -CA extra-ca.pem -CAkey extra-ca.key -CAcreateserial -out expiredclient.pem \
		-not_before 20200101000000Z -not_after 20200201000000Z 2>/dev/null
	extra_p12 extra-expired-client-3des.p12 expiredclient "$pass" "${tdes[@]}"

	cd .. && rm -rf out-extra
	echo "Extra fixtures generated."
}

if [ "$EXTRAS_ONLY" = 1 ]; then
	extras
	exit 0
fi

if true; then
PASS="jellyfin"
UNICODE_PASS="zażółć-ü"
DAYS=7300

subj() { echo "/CN=$1/O=Jellyfin TLS Fixtures"; }

# --- PKI -------------------------------------------------------------------------------------------------------------

# Server PKI: root -> intermediate -> leaf
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days $DAYS -subj "$(subj 'Fixture Root CA')" \
	-addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -keyout intermediate.key -out intermediate.csr -subj "$(subj 'Fixture Intermediate CA')" 2>/dev/null
openssl x509 -req -in intermediate.csr -CA root.pem -CAkey root.key -CAcreateserial -out intermediate.pem -days $DAYS \
	-extfile <(printf "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign") 2>/dev/null

leaf() { # name, san, extra x509 args...
	local name=$1 san=$2; shift 2
	openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "$(subj "$name")" 2>/dev/null
	openssl x509 -req -in "$name.csr" -CA intermediate.pem -CAkey intermediate.key -CAcreateserial -out "$name.pem" "$@" \
		-extfile <(printf "basicConstraints=CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s" "$san") 2>/dev/null
	cat "$name.pem" intermediate.pem > "$name-chain.pem"
}
leaf server "DNS:localhost,IP:127.0.0.1,IP:::1" -days $DAYS
leaf server-wrong-host "DNS:wrong.example" -days $DAYS
leaf server-expired "DNS:localhost,IP:127.0.0.1" -not_before 20200101000000Z -not_after 20200201000000Z

# Server key stores (3DES/SHA-1 is readable on every Android version) for the instrumented test servers
for name in server server-wrong-host server-expired; do
	openssl pkcs12 -export -inkey "$name.key" -in "$name-chain.pem" -out "$name.p12" -passout "pass:$PASS" -name server \
		-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
done

# Unrelated CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout other-ca.key -out other-ca.pem -days $DAYS -subj "$(subj 'Other CA')" \
	-addext "basicConstraints=critical,CA:true" 2>/dev/null

# Expired CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout expired-ca.key -out expired-ca.pem -subj "$(subj 'Expired CA')" \
	-addext "basicConstraints=critical,CA:true" -not_before 20200101000000Z -not_after 20200201000000Z 2>/dev/null

# Client PKI
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout client-ca.key -out client-ca.pem -days $DAYS \
	-subj "$(subj 'Fixture Client CA')" -addext "basicConstraints=critical,CA:true" 2>/dev/null

client() { # name, keygen args...
	local name=$1; shift
	openssl genpkey "$@" -out "$name.key" 2>/dev/null
	openssl req -new -key "$name.key" -out "$name.csr" -subj "$(subj "$name")" 2>/dev/null
	openssl x509 -req -in "$name.csr" -CA client-ca.pem -CAkey client-ca.key -CAcreateserial -out "$name.pem" -days $DAYS \
		-extfile <(printf "basicConstraints=CA:false\nextendedKeyUsage=clientAuth") 2>/dev/null
}
client client-rsa2048 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
client client-rsa4096 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
client client-rsa1024 -algorithm RSA -pkeyopt rsa_keygen_bits:1024
client client-ec256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
client client-ec384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
client client-ec521 -algorithm EC -pkeyopt ec_paramgen_curve:P-521
client client-ed25519 -algorithm ED25519

# --- CA import formats -----------------------------------------------------------------------------------------------

mkdir -p ../ca
cp root.pem ../ca/single.pem
cat root.pem intermediate.pem > ../ca/bundle.pem
sed 's/$/\r/' root.pem > ../ca/crlf.pem
printf '\xEF\xBB\xBF' | cat - root.pem > ../ca/bom.pem
openssl x509 -in root.pem -text > ../ca/with-text.pem
openssl x509 -in root.pem -outform DER -out ../ca/single.der
cp ../ca/single.der ../ca/single.cer
openssl crl2pkcs7 -nocrl -certfile root.pem -certfile intermediate.pem -out ../ca/bundle.p7b
openssl crl2pkcs7 -nocrl -certfile root.pem -certfile intermediate.pem -outform DER -out ../ca/bundle-der.p7b
cp server.pem ../ca/leaf-not-ca.pem
cp expired-ca.pem ../ca/expired.pem
cp other-ca.pem ../ca/other.pem
cp client-ca.pem ../ca/client-ca.pem
head -c 512 /dev/urandom > ../ca/garbage.bin
: > ../ca/empty.pem
cp root.key ../ca/private-key-only.pem

# --- Client PKCS#12 matrix -------------------------------------------------------------------------------------------

mkdir -p ../client
p12() { # output, key, cert, password, extra args...
	local out=$1 key=$2 cert=$3 password=$4; shift 4
	openssl pkcs12 -export -inkey "$key" -in "$cert" -out "../client/$out" -passout "pass:$password" -name client "$@"
}

for key in rsa2048 rsa4096 rsa1024 ec256 ec384 ec521 ed25519; do
	cat "client-$key.pem" client-ca.pem > "client-$key-chain.pem"
	p12 "$key-aes.p12" "client-$key.key" "client-$key-chain.pem" "$PASS"
	p12 "$key-legacy.p12" "client-$key.key" "client-$key-chain.pem" "$PASS" -legacy
	p12 "$key-3des.p12" "client-$key.key" "client-$key-chain.pem" "$PASS" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
	p12 "$key-nopbe.p12" "client-$key.key" "client-$key-chain.pem" "$PASS" -certpbe NONE -keypbe NONE
done

# Password variants
p12 rsa2048-empty-password.p12 client-rsa2048.key client-rsa2048-chain.pem "" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
p12 rsa2048-unicode-password.p12 client-rsa2048.key client-rsa2048-chain.pem "$UNICODE_PASS"

# Chain variants
p12 ec256-leaf-only.p12 client-ec256.key client-ec256.pem "$PASS"
cat client-ca.pem client-ec256.pem > client-ec256-reversed.pem
p12 ec256-reversed-chain.p12 client-ec256.key client-ec256-reversed.pem "$PASS"

# Certificate without key
openssl pkcs12 -export -nokeys -in client-ec256.pem -out ../client/cert-only.p12 -passout "pass:$PASS"

# Two keys in one file (legacy 3DES encryption so it is readable on every Android version)
keytool -J-Dkeystore.pkcs12.legacy -importkeystore -srckeystore ../client/ec256-3des.p12 -srcstoretype PKCS12 -srcstorepass "$PASS" -srcalias client \
	-destkeystore ../client/two-keys.p12 -deststoretype PKCS12 -deststorepass "$PASS" -destalias first -noprompt 2>/dev/null
keytool -J-Dkeystore.pkcs12.legacy -importkeystore -srckeystore ../client/rsa2048-3des.p12 -srcstoretype PKCS12 -srcstorepass "$PASS" -srcalias client \
	-destkeystore ../client/two-keys.p12 -deststoretype PKCS12 -deststorepass "$PASS" -destalias second -noprompt 2>/dev/null

# PEM key + certificate picked as client certificate
cat client-ec256.key client-ec256.pem > ../client/pem-key-and-cert.pem

# --- Server material for instrumented tests --------------------------------------------------------------------------

mkdir -p ../server
cp server.p12 server-wrong-host.p12 server-expired.p12 ../server/
cp root.pem ../server/root.pem
cp client-ca.pem ../server/client-ca.pem

cd .. && rm -rf out
echo "Fixtures generated."
fi

extras
