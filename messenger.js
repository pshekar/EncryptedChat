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
    /*
     * Need to add data members for the sending and receiving chains
     *  - When a message is sent or received, a symmetric-key ratchet step is applied to the sending or receiving chain to derive the message key.
     *  - When a new ratchet public key is received, a DH ratchet step is performed prior to the symmetric-key ratchet to replace the chain keys.
    */
    this.sending_chain = {}; // need separate chains for each line of communication->index by username?
    this.receiving_chain = {};
    this.root_chain = {};
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
    let tmp_key = {};

    if (!this.conns.hasOwnProperty(name)) { // if there hasn't been previous communication
        // setup the session by generating the necessary double ratchet keys according to the Signal spec
        // use X3DH to agree on shared secret key?
        // assuming we need to store the root key (SK) and DH shared key in this.conns, but how to generate/ share between Alice and Bob?
        this.conns[name] = true;
        DHKey = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
        if (!DHKey) {
            throw ("computeDH: Invalid key!");
        }

        tmp_key = await HMACtoHMACKey(this.EGKeyPair.sec, govEncryptionDataStr);

        if (!tmp_key) {
            throw ("HMACtoHMACKey: Invalid key!");
        }

        [this.root_chain[name], this.sending_chain[name]] = await HKDF(tmp_key, DHKey);

        if (!this.root_chain[name] || !this.sending_chain[name]) {
            throw ("HKDF: Invalid key!");
        }
        // generate a new ratchet key pair (assuming DH key?)
        // feed DH output to root KDF along with current root key (is this the shared secret key?)
        // HKDF outputs new root key (store as secret key?) and sending chain key (store in sending chain?)
    }

    let msg_key;
    [this.sending_chain[name], msg_key] = await HKDF(this.root_chain[name], this.sending_chain[name]);
    //const [a, b] = await HKDF(DHKey, tmp_key);

    if (!this.sending_chain[name] || !msg_key) {
        throw ("HKDF: Invalid key!");
    }

    // apply "symmetric-key ratchet step" to current sending chain key
        // result is new message key
        // new chain key stored, message key and old chain key deleted-> which do we store?

    // convert the HMAC output of the DH key to an AES key for encryption
    const AESKey = await HMACtoAESKey(msg_key, govEncryptionDataStr);
    if (!AESKey) {
        throw ("HMACtoAESKey: Invalid key!");
    }
    // this can probably be optimized, needs to be called for the gov encryption
    const AESKeyArrayBuffer = await HMACtoAESKey(msg_key, govEncryptionDataStr, true);
    if (!AESKeyArrayBuffer) {
        throw ("HMACtoAESKey: Invalid key!");
    }

    // now that the session has been established (or if it already was),
    // encrypt and send the message

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
    header["cGov"] = govCipher;

    // now that the government stuff is done in the header, encrypt the message 
    const ciphertext = await encryptWithGCM(AESKey, plaintext, iv, JSON.stringify(header));
    if (!ciphertext) {
        throw ("encryptWithGCM(): Invalid ciphertext!");
    }

    this.Ns++;

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
    let DHKey = "";
    if (!this.conns.hasOwnProperty(name)) { // if there hasn't been previous communication
        // setup the session by generating the necessary double ratchet keys according to the Signal spec
        // use X3DH to agree on shared secret key?
        // assuming we need to store the root key (SK) and DH shared key in this.conns, but how to generate/ share between Alice and Bob?
        //
        this.conns[name] = true;
        DHKey = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
        if (!DHKey) {
            throw ("computeDH: Invalid key!");
        }

        tmp_key = await HMACtoHMACKey(this.EGKeyPair.sec, govEncryptionDataStr);

        if (!tmp_key) {
            throw ("HMACtoHMACKey: Invalid key!");
        }

        [this.root_chain[name], this.receiving_chain[name]] = await HKDF(tmp_key, DHKey);

        if (!this.root_chain[name] || !this.receiving_chain[name]) {
            throw ("HKDF: Invalid key!");
        }
        //
    }

    // have to derive new sending and receiving chain keys when we receive a new message????

    let msg_key;
    [this.receiving_chain[name], msg_key] = await HKDF(this.root_chain[name], this.receiving_chain[name]);
    //const [a, b] = await HKDF(DHKey, tmp_key);

    if (!this.receiving_chain[name] || !msg_key) {
        throw ("HKDF: Invalid key!");
    }

    // convert the HMAC output of the DH key to an AES key for encryption
    const AESKey = await HMACtoAESKey(msg_key, govEncryptionDataStr);
    if (!AESKey) {
        throw ("HMACtoAESKey: Invalid key!");
    }

    // decrypt the ciphertext
    const plaintext = await decryptWithGCM(AESKey, ciphertext, header.receiver_iv, JSON.stringify(header));
    if (plaintext) {
        this.Nr++;
        return byteArrayToString(plaintext);
    } else {
        throw("decryptWithGCM: Invalid plaintext!");
    }
}
};