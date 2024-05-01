"use strict";

// `<encryption
//     xmlns="http://schemas.microsoft.com/office/2006/encryption"
//     xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password"
//     xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
//     <keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="RL3jtFlXRRCcHsbK+qRC3g=="/>
//     <dataIntegrity encryptedHmacKey="a5BVpFo7DyONZnWWsWo5jHQbm3GB/bz65nooAx90Cc3ZZWOOJvdpqBa4sjUUzBu6L/oRoNEcebpc2gCH4gXpBg==" encryptedHmacValue="4Lpprnxr94jITJbv2eFe8xRV/wNQ1eYDakJUQjGHF2NQTqyUFMK+EfJ4TEzHo34EFhWMSZJ/TMVq+x1g5C01cw=="/>
//     <keyEncryptors>
//         <keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
//             <p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="Sjiwa9DpbAgtT2U7FyJkfA=="
// encryptedVerifierHashInput="ZB62f8MdYZCZwRoeJiChwg==" encryptedVerifierHashValue="sBn8zqKTHGQoCMOfe6Ptlq3n5mLZCx7gRHApQl6CXfvDJolmrsV3/V6/t/spLvRDBR8dcHUySjIHJXIf4ukSmw==" encryptedKeyValue="cqG2QhdLnOd0ENWGT+UMM/lAIlqSxmIKIN7inUuApZU="/>
//         </keyEncryptor>
//     </keyEncryptors>
// </encryption>`
/**
 * @desc
 * @param {string} xml
 */
exports.getAgileEncInfo = function getAgileEncInfo(xml) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, "application/xml");
  const encryption = doc.getElementsByTagName("encryption")[0];

  let keyData = {};
  let keyEncryptors = {};
  for (
    let i = 0;
    i < encryption.getElementsByTagName("keyData")[0].attributes.length;
    i++
  ) {
    keyData[encryption.getElementsByTagName("keyData")[0].attributes[i].name] =
      encryption.getElementsByTagName("keyData")[0].attributes[i].value;
  }
  let encryptedKey = encryption
    .getElementsByTagName("keyEncryptors")[0]
    .getElementsByTagName("keyEncryptor")[0]
    .getElementsByTagName("p:encryptedKey")[0].attributes;
  console.log(encryptedKey);
  for (let i = 0; i < encryptedKey.length; i++) {
    keyEncryptors[encryptedKey[i].name] = encryptedKey[i].value;
  }

  return {
    keyData,
    keyEncryptors,
  };
};
