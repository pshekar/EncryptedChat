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
async sendMessage(name, plaintext) {
    const header = {};
    const ciphertext = "";
    // can assume we already have receiver's certificate, and they have our's

    
    if (!this.conns.hasOwnProperty(name)) { // if there hasn't been previous communication
        // setup the session by generating the necessary double ratchet keys according to the Signal spec
            // use X3DH to agree on shared secret key?
            // assuming we need to store the root key (SK) and DH shared key in this.conns, but how to generate/ share between Alice and Bob?
    }
    

    // now that the session has been established, or if it already was
    // do the message sending things
        

    return [header, ciphertext];
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
    throw("not implemented!");
    return plaintext;
}
};