"use strict";

/********* Imports ********/

import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  printCryptoKey, // async
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
} from "./lib";

import { govEncryptionDataStr } from "./lib";

/********* Implementation ********/

export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
    this.Ns = 0; // number of messages sent
    this.Nr = 0; // number of messages received
  }

/**
* Generate a certificate to be stored with the certificate authority.
* The certificate must contain the field "username".
*
* Arguments:
*   username: string
*
* Return Type: certificate object/dictionary
*/
async generateCertificate(username) {
    const certificate = {};
    const key_pair = await generateEG();
    certificate.username = username;
    certificate.pub = key_pair.pub;
    this.EGKeyPair = key_pair; // any reason to store multiple of these?

    return certificate;
}

/**
* Receive and store another user's certificate.
*
* Arguments:
*   certificate: certificate object/dictionary
*   signature: string
*
* Return Type: void
*/
async receiveCertificate(certificate, signature) {
    const result = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature);
    if (result) {
        this.certs[certificate.username] = certificate;
        // probably add to conns here?
    } else {
        throw ("verifyWithECDSA(): Invalid certificate!");
    }
}

/**
* Generate the message to be sent to another user.
*
* Arguments:
*   name: string
*   plaintext: string
*
* Return Type: Tuple of [dictionary, string]
*/
// we can assume we already have receiver's certificate, and they have our's
async sendMessage(name, plaintext) {
    const iv = genRandomSalt();
    // separate IV for government cipher
    const govIV = genRandomSalt();
    let DHKey = "";
    const header = {
        "vGov": this.EGKeyPair.pub,
        "ivGov": govIV,
        "receiver_iv": iv,
    };

    if (!this.conns.hasOwnProperty(name)) { // if there hasn't been previous communication
        // setup the session by generating the necessary double ratchet keys according to the Signal spec
        // use X3DH to agree on shared secret key?
        // assuming we need to store the root key (SK) and DH shared key in this.conns, but how to generate/ share between Alice and Bob?
        DHKey = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
        if (!DHKey) {
            throw ("computeDH: Invalid key!");
        }
    }
    // convert the HMAC output of the DH key to an AES key for encryption
    const AESKey = await HMACtoAESKey(DHKey, govEncryptionDataStr);
    if (!AESKey) {
        throw ("HMACtoAESKey: Invalid key!");
    }
    // this can probably be optimized, needs to be called for the gov encryption
    const AESKeyArrayBuffer = await HMACtoAESKey(DHKey, govEncryptionDataStr, true);
    if (!AESKeyArrayBuffer) {
        throw ("HMACtoAESKey: Invalid key!");
    }

    // now that the session has been established (or if it already was),
    // encrypt and send the message
    const ciphertext = await encryptWithGCM(AESKey, plaintext, iv);
    if (ciphertext) {
        // govDecrypt calls decrypt twice for some reason so im encrypting here again?
        // this is cuz we need to encrypt the original AESKey again for the gov cipher
        const DHKeyGov = await computeDH(this.EGKeyPair.sec, this.govPublicKey);
        if (!DHKey) {
            throw ("computeDH: Invalid key!");
        }
        const AESKeyGov = await HMACtoAESKey(DHKeyGov, govEncryptionDataStr);
        if (!AESKeyGov) {
            throw ("HMACtoAESKey: Invalid key!");
        }
        const govCipher = await encryptWithGCM(AESKeyGov, AESKeyArrayBuffer, govIV);
        if (!govCipher) {
            throw("encryptWithGCM(): Invalid ciphertext!");
        }
        
        // add cGov to the header once computed
        header["cGov"]= govCipher;
        this.Ns++;
        return [header, ciphertext];
    } else {
        throw("encryptWithGCM(): Invalid ciphertext!");
    }
}


/**
* Decrypt a message received from another user.
*
* Arguments:
*   name: string
*   [header, ciphertext]: Tuple of [dictionary, string]
*
* Return Type: string
*/
async receiveMessage(name, [header, ciphertext]) {
    let DHKey = "";
    if (!this.conns.hasOwnProperty(name)) { // if there hasn't been previous communication
        // setup the session by generating the necessary double ratchet keys according to the Signal spec
        // use X3DH to agree on shared secret key?
        // assuming we need to store the root key (SK) and DH shared key in this.conns, but how to generate/ share between Alice and Bob?
        DHKey = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
        if (!DHKey) {
            throw ("computeDH: Invalid key!");
        }
    }
    // convert the HMAC output of the DH key to an AES key for encryption
    const AESKey = await HMACtoAESKey(DHKey, govEncryptionDataStr);
    if (!AESKey) {
        throw ("HMACtoAESKey: Invalid key!");
    }

    // decrypt the ciphertext
    const plaintext = await decryptWithGCM(AESKey, ciphertext, header.receiver_iv);
    if (plaintext) {
        this.Nr++;
        return byteArrayToString(plaintext);
    } else {
        throw("decryptWithGCM: Invalid plaintext!");
    }
}
};