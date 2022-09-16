// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// Generated using:
//
//	openssl genrsa 1024 | openssl pkcs8 -topk8 -nocrypt
var pkcs8RSAPrivateKeyHex = `30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031`

// Generated using:
//
//	openssl ecparam -genkey -name secp224r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P224PrivateKeyHex = `3078020100301006072a8648ce3d020106052b810400210461305f020101041cca3d72b3e88fed2684576dad9b80a9180363a5424986900e3abcab3fa13c033a0004f8f2a6372872a4e61263ed893afb919576a4cacfecd6c081a2cbc76873cf4ba8530703c6042b3a00e2205087e87d2435d2e339e25702fae1`

// Generated using:
//
//	openssl ecparam -genkey -name secp256r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P256PrivateKeyHex = `308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43a14403420004b9c9b90095476afe7b860d8bd43568cab7bcb2eed7b8bf2fa0ce1762dd20b04193f859d2d782b1e4cbfd48492f1f533113a6804903f292258513837f07fda735`

// Generated using:
//
//	openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P384PrivateKeyHex = `3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309bf832f6aaaeacb78ce47ffb15e6fd0fd48683ae79df6eca39bfb8e33829ac94aa29d08911568684c2264a08a4ceb679a164036200049070ad4ed993c7770d700e9f6dc2baa83f63dd165b5507f98e8ff29b5d2e78ccbe05c8ddc955dbf0f7497e8222cfa49314fe4e269459f8e880147f70d785e530f2939e4bf9f838325bb1a80ad4cf59272ae0e5efe9a9dc33d874492596304bd3`

// Generated using:
//
//	openssl ecparam -genkey -name secp521r1 | openssl pkcs8 -topk8 -nocrypt
//
// Note that OpenSSL will truncate the private key if it can (i.e. it emits it
// like an integer, even though it's an OCTET STRING field). Thus if you
// regenerate this you may, randomly, find that it's a byte shorter than
// expected and the Go test will fail to recreate it exactly.
var pkcs8P521PrivateKeyHex = `3081ee020100301006072a8648ce3d020106052b810400230481d63081d3020101044200cfe0b87113a205cf291bb9a8cd1a74ac6c7b2ebb8199aaa9a5010d8b8012276fa3c22ac913369fa61beec2a3b8b4516bc049bde4fb3b745ac11b56ab23ac52e361a1818903818600040138f75acdd03fbafa4f047a8e4b272ba9d555c667962b76f6f232911a5786a0964e5edea6bd21a6f8725720958de049c6e3e6661c1c91b227cebee916c0319ed6ca003db0a3206d372229baf9dd25d868bf81140a518114803ce40c1855074d68c4e9dab9e65efba7064c703b400f1767f217dac82715ac1f6d88c74baf47a7971de4ea`

// Generated using:
//
//	openssl genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:2048 | openssl pkcs8 -topk8 -nocrypt -outform DER | xxd -p
var pkcs8RSAPSSPrivateKeyHex = `308204bb020100300b06092a864886f70d01010a048204a7308204a30201000282010100b7a13ad83498ce2490f615ca6938910a351292d48cf120c3f8f489f274ceb7504e4348d27dbf614daf418590f7f4b544d1f404a329eb2161346e3656a90d30433d5916bfb1045a9dd8a62698f0404ddab87d3c6926110726c1e46093881bc38140120e711b37f30c6f3decaf83e0d146decde547144886860bad8e801682c80c221910862e89bc124702460a12e2fabc5d1095583394b16b4610121435defe4f1e239c75de23e40ece90fc178b899b4aa025fddcc5fb08741bc7e9e9cbf1ca92e29b9b6d98f5a735ad7f004cd283fc6fe7a69509b3e5dec3119b34a5e05bf7c10d2695a4d305ee8a55460cefd789e10f30aa6bc0582614a9ca9f54b62ed431f502030100010282010008c232b4e9cb53b7cd9c98925092ff635c7fda8b88a91ea8e248c304a81acd0667a3e61c6372e655fc283f51edc06e5df8e2af4ef0affe50ad32c83a3972d4d766dcc73794f3fccb7f1ad65d4b4651eaff0b9029ac19b9fcd8ae31dcba41a816a938434294abb0ec29fe8039d3413cfcd3a1eaa5498677b8d08e9d17a71b37fb3c1b73acfa2343e5ee08266f78da2803c3f5bfe0d28bad9bbc2df9ce26cf6552110fbd045e98add8ccd41e5ee98c434a661b74eba48d776c72c06ce1299058ff0636f7f5cd0d3fca93c61459f3ebdf4ee93e7ad9c04889ed48e24949ba0c8ad66477e18dd6ae6a6be1063506dd9e6610d6689fb621b88335a5e9e274abb799b902818100e82f443ea702130d7be7f5815b092d6522fc2b2df471bf4f139d54d51157a46ec03148e8ddc424692d36fc1634e2136d9c28a5d317c1b28a426b2dec20ebfc06242aa5d063f363330c88069e13806d4bfae02985fe499c225dda81f9685f1f29b2ac4f49d77d93c28e08acebd653767be0b39da0a33bf3b76434b65d5049df0d02818100ca770120ec859de0e87f34cf200a0cbc10390c928fa065d45649a7efba6f77bb0835ecd12d69aee32766c5eb004edd3f43d6e0b88b5909c1d79922b1e600286d6dc0fa5b0a7cb14990da3f33ebb913903a6164bef87d249ed9027402316989c3ce02ad7545b9247e4b7428c7152aad2a31b329b41d557207fd735129982624890281802221a0a49d245eeca2844cc0c1432e1b29f36bdd8b8b9515e8ca3e083c4e67eba7f116c8b4a0fac143564be46fcdb4116edd42d32f30d8301ee7668ec9a0272237fad4f937583602f11aa5ee62eb8425a13186a91de27043550ca402a7e723cb9b6a5d157bca0808979c8adef858b8982945fe2bf912fd16be7249449a62e19902818065af5d36bef3e0b63baedfc4033068f2ef26e7e4981413f09021d0217bbe4e20f65fb6ffdbd20f4ef0d4122513f387f5254a3f75102f78d20d4950fe8e28982555912d6c1a1944255185fb6645469fc7b93a7f11d6d56b560861ce07e7ef3c8cc5e3dc6060d33abbdf8388936c5311c37650a86a58ad386740e8f0e37611fa1902818100e4295b01192a35b7d75b6622118b03f70f067b314a1b90df372f97a77d2a8eb7d16bd039e86e23d07b4f7952099f3d5a052005c3bbfdbb02c426c3a641b876cd8f3568e266b6fdf0f2e2ac1b3ff79cc9b354d716abed99b347308d1a651a863e78aa3942af1f68c7de15ce96de9e3ecf7662281f444de266cefd31055186a2d8`

// From RFC 8410, Section 7.
var pkcs8Ed25519PrivateKeyHex = `302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842`

func TestPKCS8(t *testing.T) {
	tests := []struct {
		name           string
		keyHex         string
		keyType        reflect.Type
		curve          elliptic.Curve
		failsRoundtrip bool
	}{
		{
			name:    "RSA private key",
			keyHex:  pkcs8RSAPrivateKeyHex,
			keyType: reflect.TypeOf(&rsa.PrivateKey{}),
		},
		{
			name:           "RSA-PSS private key",
			keyHex:         pkcs8RSAPSSPrivateKeyHex,
			keyType:        reflect.TypeOf(&rsa.PrivateKey{}),
			failsRoundtrip: true,
		},
		{
			name:    "P-224 private key",
			keyHex:  pkcs8P224PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P224(),
		},
		{
			name:    "P-256 private key",
			keyHex:  pkcs8P256PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P256(),
		},
		{
			name:    "P-384 private key",
			keyHex:  pkcs8P384PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P384(),
		},
		{
			name:    "P-521 private key",
			keyHex:  pkcs8P521PrivateKeyHex,
			keyType: reflect.TypeOf(&ecdsa.PrivateKey{}),
			curve:   elliptic.P521(),
		},
		{
			name:    "Ed25519 private key",
			keyHex:  pkcs8Ed25519PrivateKeyHex,
			keyType: reflect.TypeOf(ed25519.PrivateKey{}),
		},
	}

	for _, test := range tests {
		derBytes, err := hex.DecodeString(test.keyHex)
		if err != nil {
			t.Errorf("%s: failed to decode hex: %s", test.name, err)
			continue
		}
		privKey, err := ParsePKCS8PrivateKey(derBytes)
		if err != nil {
			t.Errorf("%s: failed to decode PKCS#8: %s", test.name, err)
			continue
		}
		if reflect.TypeOf(privKey) != test.keyType {
			t.Errorf("%s: decoded PKCS#8 returned unexpected key type: %T", test.name, privKey)
			continue
		}
		if ecKey, isEC := privKey.(*ecdsa.PrivateKey); isEC && ecKey.Curve != test.curve {
			t.Errorf("%s: decoded PKCS#8 returned unexpected curve %#v", test.name, ecKey.Curve)
			continue
		}
		reserialised, err := MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			t.Errorf("%s: failed to marshal into PKCS#8: %s", test.name, err)
			continue
		}
		if !test.failsRoundtrip && !bytes.Equal(derBytes, reserialised) {
			t.Errorf("%s: marshaled PKCS#8 didn't match original: got %x, want %x", test.name, reserialised, derBytes)
			continue
		}
	}
}

const hexPKCS8TestPKCS1Key = "3082025c02010002818100b1a1e0945b9289c4d3f1329f8a982c4a2dcd59bfd372fb8085a9c517554607ebd2f7990eef216ac9f4605f71a03b04f42a5255b158cf8e0844191f5119348baa44c35056e20609bcf9510f30ead4b481c81d7865fb27b8e0090e112b717f3ee08cdfc4012da1f1f7cf2a1bc34c73a54a12b06372d09714742dd7895eadde4aa5020301000102818062b7fa1db93e993e40237de4d89b7591cc1ea1d04fed4904c643f17ae4334557b4295270d0491c161cb02a9af557978b32b20b59c267a721c4e6c956c2d147046e9ae5f2da36db0106d70021fa9343455f8f973a4b355a26fd19e6b39dee0405ea2b32deddf0f4817759ef705d02b34faab9ca93c6766e9f722290f119f34449024100d9c29a4a013a90e35fd1be14a3f747c589fac613a695282d61812a711906b8a0876c6181f0333ca1066596f57bff47e7cfcabf19c0fc69d9cd76df743038b3cb024100d0d3546fecf879b5551f2bd2c05e6385f2718a08a6face3d2aecc9d7e03645a480a46c81662c12ad6bd6901e3bd4f38029462de7290859567cdf371c79088d4f024100c254150657e460ea58573fcf01a82a4791e3d6223135c8bdfed69afe84fbe7857274f8eb5165180507455f9b4105c6b08b51fe8a481bb986a202245576b713530240045700003b7a867d0041df9547ae2e7f50248febd21c9040b12dae9c2feab0d3d4609668b208e4727a3541557f84d372ac68eaf74ce1018a4c9a0ef92682c8fd02405769731480bb3a4570abf422527c5f34bf732fa6c1e08cc322753c511ce055fac20fc770025663ad3165324314df907f1f1942f0448a7e9cdbf87ecd98b92156"
const hexPKCS8TestECKey = "3081a40201010430bdb9839c08ee793d1157886a7a758a3c8b2a17a4df48f17ace57c72c56b4723cf21dcda21d4e1ad57ff034f19fcfd98ea00706052b81040022a16403620004feea808b5ee2429cfcce13c32160e1c960990bd050bb0fdf7222f3decd0a55008e32a6aa3c9062051c4cba92a7a3b178b24567412d43cdd2f882fa5addddd726fe3e208d2c26d733a773a597abb749714df7256ead5105fa6e7b3650de236b50"

var pkcs8MismatchKeyTests = []struct {
	hexKey        string
	errorContains string
}{
	{hexKey: hexPKCS8TestECKey, errorContains: "use ParseECPrivateKey instead"},
	{hexKey: hexPKCS8TestPKCS1Key, errorContains: "use ParsePKCS1PrivateKey instead"},
}

func TestPKCS8MismatchKeyFormat(t *testing.T) {
	for i, test := range pkcs8MismatchKeyTests {
		derBytes, _ := hex.DecodeString(test.hexKey)
		_, err := ParsePKCS8PrivateKey(derBytes)
		if !strings.Contains(err.Error(), test.errorContains) {
			t.Errorf("#%d: expected error containing %q, got %s", i, test.errorContains, err)
		}
	}
}
