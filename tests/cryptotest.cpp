
#include "gtest.h"

namespace Test {

#include "../libpubnub/crypto.c"

class CryptoTest : public ::testing::Test
{
protected:
	void encryptTest(const char *src, const char *exp) {
		msg = pubnub_encrypt("enigma", src);
		ASSERT_TRUE(msg);
		EXPECT_STREQ(exp, json_object_get_string(msg));
		json_object_put(msg);
	}
	struct json_object *msg;
};

TEST_F(CryptoTest, Sample1) {
	encryptTest("{}", "IDjZE9BHSjcX67RddfCYYg==");
}

TEST_F(CryptoTest, Sample2) {
	encryptTest("[]", "Ns4TB41JjT2NCXaGLWSPAQ==");
}

TEST_F(CryptoTest, StringTest) {
	encryptTest("\"Pubnub Messaging API 1\"", "f42pIQcWZ9zbTbH8cyLwByD/GsviOE0vcREIEVPARR0=");
}

TEST_F(CryptoTest, ObjectTest) {
	encryptTest("{\"this stuff\":{\"can get\":\"complicated!\"}}", "zMqH/RTPlC8yrAZ2UhpEgLKUVzkMI2cikiaVg30AyUu7B6J0FLqCazRzDOmrsFsF");
}

TEST_F(CryptoTest, ArrayTest) {
	msg = json_object_new_array();
	json_object_array_add(msg, json_object_new_string("Ns4TB41JjT2NCXaGLWSPAQ=="));
	struct json_object *newa = pubnub_decrypt_array("enigma", msg);
	ASSERT_TRUE(msg);
	EXPECT_STREQ("[ ]", json_object_get_string(json_object_array_get_idx(newa, 0)));
}

class SignatureTest : public ::testing::Test
{
protected:
	virtual void SetUp() {
		signature = NULL;
		p.publish_key = strdup("pub_key");
		p.subscribe_key = strdup("sub_key");
		p.secret_key = strdup("#12345#");
	}
	virtual void TearDown() {
		free(signature);
		free(p.publish_key);
		free(p.subscribe_key);
		free(p.secret_key);
	}

	struct pubnub p;
	char *signature;
};

TEST_F(SignatureTest, Sample1) {
	signature = pubnub_signature(&p, "enigma", "{message:\"Message\"}");
	EXPECT_STREQ(signature, "7d40b6468716629f53828b2054c51198");
}

TEST_F(SignatureTest, Sample2) {
	p.secret_key[0] = 0;
	signature = pubnub_signature(&p, "enigma", "{number1:10, number2: 20}");
	EXPECT_STREQ(signature, "f32a2342e1202a48a5a037846b278927");
}

}
