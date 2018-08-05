package srp

import (
	"crypto/sha1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test vector from https://www.ietf.org/rfc/rfc5054.txt
var username = "alice"
var password = "password123"
var salt = getBigIntFromHex("BEB25379 D1A8581E B5A72767 3A2441EE").Bytes()
var prime = getBigIntFromHex("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B 9FC61D2F C0EB06E3")
var generator = getBigIntFromHex("2")
var multiplier = getBigIntFromHex("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F")
var x = getBigIntFromHex("94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124")
var xWithoutUsername = getBigIntFromHex("BF56D7DF 933FF138 C4ED956E 26D2576D BBE8530B")
var verifier = getBigIntFromHex("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812 9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5 C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5 EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78 E955A5E2 9E7AB245 DB2BE315 E2099AFB")
var privateClientValue = getBigIntFromHex("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393")
var privateServerValue = getBigIntFromHex("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20")
var publicClientValue = getBigIntFromHex("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B")
var publicServerValue = getBigIntFromHex("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011 BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99 6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA 37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE EB4012B7 D7665238 A8E3FB00 4B117B58")
var scramblingParameter = getBigIntFromHex("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019")
var premasterSecret = getBigIntFromHex("B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D 233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C 41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F 3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D C346D7E4 74B29EDE 8A469FFE CA686E5A")
var clientEvidence = getBigIntFromHex("B46A7838 46B7E569 FF8F9B44 AB8D88ED EB085A65")
var serverEvidence = getBigIntFromHex("B0A6AD30 24E79b5C AD04042A BB3A3F59 2D20C17")

var srpGroups = map[string]*Group{
	"rfc-1024": &Group{
		Prime:     getBigIntFromHex("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B 9FC61D2F C0EB06E3"),
		Generator: getBigIntFromHex("2"),
	},
	"rfc-1536": &Group{
		Prime:     getBigIntFromHex("9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961 4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843 80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5 6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E 8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB"),
		Generator: getBigIntFromHex("2"),
	},
	"rfc-2048": &Group{
		Prime:     getBigIntFromHex("AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294 3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74 7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A 436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D 5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73 03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6 94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F 9E4AFF73"),
		Generator: getBigIntFromHex("2"),
	},
	"rfc-3072": &Group{
		Prime:     getBigIntFromHex("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"),
		Generator: getBigIntFromHex("5"),
	},
	"rfc-4096": &Group{
		Prime:     getBigIntFromHex("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199 FFFFFFFF FFFFFFFF"),
		Generator: getBigIntFromHex("5"),
	},
	"rfc-6144": &Group{
		Prime:     getBigIntFromHex("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492 36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E 6DCC4024 FFFFFFFF FFFFFFFF"),
		Generator: getBigIntFromHex("5"),
	},
	"rfc-8192": &Group{
		Prime:     getBigIntFromHex("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492 36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9 22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71 60C980DD 98EDD3DF FFFFFFFF FFFFFFFF"),
		Generator: getBigIntFromHex("12"),
	},
}

func TestWithVector(t *testing.T) {
	var h = sha1.New

	assert.Equal(t, multiplier, computeMultiplier(h, prime, generator))
	assert.Equal(t, x, computeXWithUsername(h, salt, username, password))
	assert.Equal(t, scramblingParameter, computeScramblingParameter(h, prime, publicClientValue, publicServerValue))
	assert.Equal(t, verifier, computeVerifier(prime, generator, x))
	assert.Equal(t, publicClientValue, computePublicClientValue(prime, generator, privateClientValue))
	assert.Equal(t, publicServerValue, computePublicServerValue(prime, generator, multiplier, verifier, privateServerValue))
	assert.Equal(t, premasterSecret, computeServerSessionKey(prime, verifier, scramblingParameter, publicClientValue, privateServerValue))
	assert.Equal(t, premasterSecret, computeClientSessionKey(prime, generator, multiplier, x, scramblingParameter, privateClientValue, publicServerValue))
}

func TestGenerateRandomSalt(t *testing.T) {
	for i := 0; i < 100; i++ {
		var salt, err = generateRandomSalt(i)
		assert.Nil(t, err)
		assert.Equal(t, i, len(salt))
	}
}

func TestComputeXWithoutUsername(t *testing.T) {
	var h = sha1.New

	var x = computeXWithoutUsername(h, salt, username, password)
	assert.Equal(t, xWithoutUsername, x)
}

func TestGeneratePrivateValue(t *testing.T) {
	var min = big.NewInt(1)
	var max = prime

	for i := 0; i < 1e6; i++ {
		var v, err = generatePrivateValue(prime)
		assert.Nil(t, err)
		// v >= min
		assert.True(t, v.Cmp(min) == 0 || v.Cmp(min) == 1)
		// v < max
		assert.True(t, v.Cmp(max) == -1)
	}
}

func TestIsValidPublicValue(t *testing.T) {
	// Test with valid values.
	assert.True(t, isValidPublicValue(prime, publicClientValue))
	assert.True(t, isValidPublicValue(prime, publicServerValue))

	// Test with invalid values (x % n == 0)
	var x = big.NewInt(0)
	for i := 0; i < 100; i++ {
		assert.False(t, isValidPublicValue(prime, x))
		x = x.Add(x, prime)
	}
}

func TestComputeClientEvidence(t *testing.T) {
	var h = sha1.New

	var e = computeClientEvidence(h, publicClientValue, publicServerValue, premasterSecret)
	assert.Equal(t, clientEvidence, e)
}

func TestComputeServerEvidence(t *testing.T) {
	var h = sha1.New

	var e = computeServerEvidence(h, publicClientValue, clientEvidence, premasterSecret)
	assert.Equal(t, serverEvidence, e)
}

func TestGetGroup(t *testing.T) {
	// Test with valid group name.
	var grpNames = []string{"rfc-1024", "rfc-1536", "rfc-2048", "rfc-3072", "rfc-4096", "rfc-6144", "rfc-8192"}

	for _, grpName := range grpNames {
		var grp, err = GetGroup(grpName)
		assert.Nil(t, err)
		assert.NotNil(t, grp.Prime)
		assert.NotNil(t, grp.Generator)
	}

	// Test with invalid group name.
	var grp, err = GetGroup("invalid")
	assert.NotNil(t, err)
	assert.Nil(t, grp)
}

func TestGetBigIntFromHex(t *testing.T) {
	var validValues = []string{"0", "ab", "AbC", "0    a"}

	for _, v := range validValues {
		var x = getBigIntFromHex(v)
		assert.NotNil(t, x)
	}

	var invalidValues = []string{"", "abcdefg", "012%"}

	for _, v := range invalidValues {
		var f = func() {
			_ = getBigIntFromHex(v)
		}
		assert.Panics(t, f)
	}

}
