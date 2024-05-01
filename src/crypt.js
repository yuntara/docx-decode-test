"use strict";

const xmlUtil = require("./xml");

const ENCRYPTION_INFO_PREFIX = Buffer.from([
  0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00,
]); // First 4 bytes are the version number, second 4 bytes are reserved.
const PACKAGE_ENCRYPTION_CHUNK_SIZE = 4096;
const PACKAGE_OFFSET = 8; // First 8 bytes are the size of the stream

// Block keys used for encryption
const BLOCK_KEYS = {
  key: Buffer.from([0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6]),
};

const Encryptor = {
  async hash(algorithm, ...buffers) {
    const data = Buffer.concat(buffers);
    if (algorithm === "SHA512") {
      algorithm = "SHA-512";
    }
    const hash = await window.crypto.subtle.digest(algorithm, data);
    const buf = Buffer.from(hash);
    return buf;
  },

  async decrypt(data, password) {
    let { encryptionInfoBuffer, encryptedPackageBuffer } = data;

    // In the browser the CFB content is an array. Convert to a Buffer.
    if (!Buffer.isBuffer(encryptionInfoBuffer))
      encryptionInfoBuffer = Buffer.from(encryptionInfoBuffer);
    if (!Buffer.isBuffer(encryptedPackageBuffer))
      encryptedPackageBuffer = Buffer.from(encryptedPackageBuffer);

    // Parse the encryption info XML into an object
    const encryptionInfo = await this.parseEncryptionInfo(encryptionInfoBuffer);

    // Convert the password into an encryption key
    const key = await this.convertPasswordToKey(
      password,
      encryptionInfo.key.hashAlgorithm,
      encryptionInfo.key.saltValue,
      encryptionInfo.key.spinCount,
      encryptionInfo.key.keyBits,
      BLOCK_KEYS.key,
    );
    console.log("passwordtokey", key);

    const importedKey = await window.crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-CBC" },
      false,
      ["decrypt"],
    );

    console.log("importedKey", importedKey);

    // Use the key to decrypt the package key
    const packageKey = await this.crypt(
      encryptionInfo.key.cipherAlgorithm,
      encryptionInfo.key.cipherChaining,
      importedKey,
      encryptionInfo.key.saltValue,
      encryptionInfo.key.encryptedKeyValue,
    );

    const importedPackageKey = await window.crypto.subtle.importKey(
      "raw",
      packageKey,
      { name: "AES-CBC" },
      false,
      ["decrypt"],
    );

    // Use the package key to decrypt the package
    return await this.cryptPackage(
      encryptionInfo.package.cipherAlgorithm,
      encryptionInfo.package.cipherChaining,
      encryptionInfo.package.hashAlgorithm,
      encryptionInfo.package.blockSize,
      encryptionInfo.package.saltValue,
      importedPackageKey,
      encryptedPackageBuffer,
    );
  },

  async parseEncryptionInfo(buffer) {
    // Pull off the prefix and convert to string
    const xml = buffer.slice(ENCRYPTION_INFO_PREFIX.length).toString("utf8");
    const doc = await xmlUtil.getAgileEncInfo(xml);

    const { keyData, keyEncryptors } = doc;
    const {
      cipherAlgorithm,
      cipherChaining,
      saltValue,
      hashAlgorithm,
      blockSize,
    } = keyData;
    const encryptedKeyNode = keyEncryptors;

    return {
      package: {
        cipherAlgorithm,
        cipherChaining,
        saltValue: Buffer.from(saltValue, "base64"),
        hashAlgorithm,
        blockSize,
      },
      key: {
        encryptedKeyValue: Buffer.from(
          encryptedKeyNode.encryptedKeyValue,
          "base64",
        ),
        cipherAlgorithm: encryptedKeyNode.cipherAlgorithm,
        cipherChaining: encryptedKeyNode.cipherChaining,
        saltValue: Buffer.from(encryptedKeyNode.saltValue, "base64"),
        hashAlgorithm: encryptedKeyNode.hashAlgorithm,
        spinCount: encryptedKeyNode.spinCount,
        keyBits: encryptedKeyNode.keyBits,
      },
    };
  },

  async convertPasswordToKey(
    password,
    hashAlgorithm,
    saltValue,
    spinCount,
    keyBits,
    blockKey,
  ) {
    // Password must be in unicode buffer
    const passwordBuffer = Buffer.from(password, "utf16le");

    console.log("convertPasswordTo");
    // Generate the initial hash
    let key = await this.hash(hashAlgorithm, saltValue, passwordBuffer);

    // Now regenerate until spin count
    for (let i = 0; i < spinCount; i++) {
      const iterator = this.createUInt32LEBuffer(i);
      key = await this.hash(hashAlgorithm, iterator, key);
    }

    // Now generate the final hash
    key = await this.hash(hashAlgorithm, key, blockKey);

    // Truncate or pad as needed to get to length of keyBits
    const keyBytes = keyBits / 8;
    if (key.length < keyBytes) {
      const tmp = Buffer.alloc(keyBytes, 0x36);
      key.copy(tmp);
      key = tmp;
    } else if (key.length > keyBytes) {
      key = key.slice(0, keyBytes);
    }

    return key;
  },

  async cryptPackage(
    cipherAlgorithm,
    cipherChaining,
    hashAlgorithm,
    blockSize,
    saltValue,
    key,
    input,
  ) {
    console.log("cryptPackage");
    // The first 8 bytes is supposed to be the length, but it seems like it is really the length - 4..
    const outputChunks = [];
    const offset = PACKAGE_OFFSET;

    // The package is encoded in chunks. Encrypt/decrypt each and concat.
    let i = 0;
    let start = 0;
    let end = 0;
    while (end < input.length) {
      start = end;
      end = start + PACKAGE_ENCRYPTION_CHUNK_SIZE;
      if (end > input.length) end = input.length;

      // Grab the next chunk
      let inputChunk = input.slice(start + offset, end + offset);

      // Pad the chunk if it is not an integer multiple of the block size
      const remainder = inputChunk.length % blockSize;
      if (remainder)
        inputChunk = Buffer.concat([
          inputChunk,
          Buffer.alloc(blockSize - remainder),
        ]);

      // Create the initialization vector
      const iv = this.createIV(hashAlgorithm, saltValue, blockSize, i);

      // Encrypt/decrypt the chunk and add it to the array
      const outputChunk = await this.crypt(
        cipherAlgorithm,
        cipherChaining,
        key,
        iv,
        inputChunk,
      );
      outputChunks.push(outputChunk);

      i++;
    }

    // Concat all of the output chunks.
    let output = Buffer.concat(outputChunks);

    if (encrypt) {
      // Put the length of the package in the first 8 bytes
      output = Buffer.concat([
        this.createUInt32LEBuffer(input.length, PACKAGE_OFFSET),
        output,
      ]);
    } else {
      // Truncate the buffer to the size in the prefix
      const length = input.readUInt32LE(0);
      output = output.slice(0, length);
    }

    return output;
  },

  createUInt32LEBuffer(value, bufferSize = 4) {
    const buffer = Buffer.alloc(bufferSize);
    buffer.writeUInt32LE(value, 0);
    return buffer;
  },

  async createIV(hashAlgorithm, saltValue, blockSize, blockKey) {
    // Create the block key from the current index
    if (typeof blockKey === "number")
      blockKey = this.createUInt32LEBuffer(blockKey);

    // Create the initialization vector by hashing the salt with the block key.
    // Truncate or pad as needed to meet the block size.
    let iv = await this.hash(hashAlgorithm, saltValue, blockKey);
    if (iv.length < blockSize) {
      const tmp = Buffer.alloc(blockSize, 0x36);
      iv.copy(tmp);
      iv = tmp;
    } else if (iv.length > blockSize) {
      iv = iv.slice(0, blockSize);
    }

    return iv;
  },

  async crypt(cipherAlgorithm, cipherChaining, key, iv, input) {
    let algorithm = `${cipherAlgorithm}-${key.algorithm.length}`;
    if (cipherChaining === "ChainingModeCBC") algorithm += "-cbc";
    else throw new Error(`Unknown cipher chaining: ${cipherChaining}`);

    console.log("algorithm", algorithm);
    console.log("crypt", input, iv, key);
    const output = await window.crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv.buffer,
      },
      key,
      input.buffer,
    );
    console.log("output", output);

    return output;
  },
};
module.exports = Encryptor;
