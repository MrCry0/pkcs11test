// Copyright 2013-2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// PKCS#11 s11.11: Signing and MACing functions
//   C_SignInit
//   C_Sign
//   C_SignUpdate
//   C_SignFinal
//   C_SignRecoverInit
//   C_SignRecover
// PKCS#11 s11.12: Functions for verifying signatures and MACs
//   C_VerifyInit
//   C_Verify
//   C_VerifyUpdate
//   C_VerifyFinal
//   C_VerifyRecoverInit
//   C_VerifyRecover
#include "pkcs11test.h"

#include <map>
#include <string>

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

namespace {

struct TestData {
  string key;  // Hex
  string data;  // Hex
  string hash;  // Hex
};

map<string, vector<TestData> > kTestVectors = {
  // Test vectors from RFC 2202.
  {"MD5-HMAC",
   {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
     "4869205468657265",
     "9294727a3638bb1c13f48ef8158bfc9d"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
     "56be34521d144c88dbb8c733f0e8b3f6"}}},
  {"SHA1-HMAC",
   {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
     "4869205468657265",
     "b617318655057264e28bc0b6fb378c8ef146be00"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
     "125d7342b9ac11cd91a39af48aa17b4f63f175d3"}}},
  // Test vectors from RFC 4231.
  {"SHA256-HMAC",
   {{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"}}},
  {"SHA384-HMAC",
   {{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
     "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
     "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"}}},
  {"SHA512-HMAC",
   {{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
     "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
     "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"}}},
};

}  // namespace

class HmacTest : public ReadOnlySessionTest,
                 public ::testing::WithParamInterface<string> {
 public:
  HmacTest()
    : attrs_({CKA_SIGN, CKA_VERIFY}),
      info_(kHmacInfo[GetParam()]),
      keylen_(64 + (std::rand() % 64)),
      key_data_(randmalloc(keylen_)),
      key_(INVALID_OBJECT_HANDLE),
      datalen_(std::rand() % 1024),
      data_(randmalloc(datalen_)),
      mechanism_({info_.hmac, NULL_PTR, 0}) {
    // Implementations generally only support HMAC with a GENERIC_SECRET key.
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    vector<CK_ATTRIBUTE> attrs = {
      {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
      {CKA_SIGN, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
      {CKA_VERIFY, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
      {CKA_VALUE, (CK_VOID_PTR)key_data_.get(), (CK_ULONG)keylen_},
    };
    EXPECT_CKR_OK(g_fns->C_CreateObject(session_, attrs.data(), attrs.size(), &key_));
  }
  ~HmacTest() {
    if (key_ != INVALID_OBJECT_HANDLE) {
      g_fns->C_DestroyObject(session_, key_);
    }
  }

 protected:
  vector<CK_ATTRIBUTE_TYPE> attrs_;
  HmacInfo info_;
  const int keylen_;
  unique_ptr<CK_BYTE, freer> key_data_;
  CK_OBJECT_HANDLE key_;
  const int datalen_;
  unique_ptr<CK_BYTE, freer> data_;
  CK_MECHANISM mechanism_;
};

#define SKIP_IF_UNIMPLEMENTED_RV(rv) \
    if ((rv) == CKR_MECHANISM_INVALID) {  \
      stringstream ss; \
      ss << "Digest type " << mechanism_type_name(mechanism_.mechanism) << " not implemented"; \
      TEST_SKIPPED(ss.str()); \
      return; \
    }

TEST_P(HmacTest, SignVerify) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, key_);
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[1024];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));
  EXPECT_EQ(info_.mac_size, output_len);

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, key_));
  EXPECT_CKR_OK(g_fns->C_Verify(session_, data_.get(), datalen_, output, output_len));
}

TEST_P(HmacTest, SignFailVerify) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, key_);
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[1024];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));

  // Corrupt one byte of the signature.
  output[0]++;

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, key_));
  EXPECT_CKR(CKR_SIGNATURE_INVALID,
             g_fns->C_Verify(session_, data_.get(), datalen_, output, output_len));
}

INSTANTIATE_TEST_CASE_P(HMACs, HmacTest,
                        ::testing::Values("MD5-HMAC",
                                          "SHA1-HMAC",
                                          "SHA256-HMAC",
                                          "SHA384-HMAC",
                                          "SHA512-HMAC"));

TEST_F(ReadOnlySessionTest, HmacTestVectors) {
  for (const auto& kv : kTestVectors) {
    vector<TestData> testcases = kTestVectors[kv.first];
    HmacInfo info = kHmacInfo[kv.first];
    for (const TestData& testcase : kv.second) {
      string key = hex_decode(testcase.key);
      CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
      CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
      vector<CK_ATTRIBUTE> attrs = {
        {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
        {CKA_SIGN, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
        {CKA_VERIFY, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
        {CKA_VALUE, (CK_VOID_PTR)key.data(), key.size()},
      };
      CK_OBJECT_HANDLE key_object;
      ASSERT_CKR_OK(g_fns->C_CreateObject(session_, attrs.data(), attrs.size(), &key_object));

      CK_MECHANISM mechanism = {info.hmac, NULL_PTR, 0};

      CK_RV rv = g_fns->C_SignInit(session_, &mechanism, key_object);
      if (rv == CKR_MECHANISM_INVALID)
        continue;
      ASSERT_CKR_OK(rv);

      string data = hex_decode(testcase.data);
      CK_BYTE output[1024];
      CK_ULONG output_len = sizeof(output);
      EXPECT_CKR_OK(g_fns->C_Sign(session_, (CK_BYTE_PTR)data.data(), data.size(), output, &output_len));
      string output_hex = hex_data(output, output_len);
      EXPECT_EQ(testcase.hash, output_hex);
    }
  }
}

}  // namespace test
}  // namespace pkcs11
