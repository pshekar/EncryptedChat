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
    // dictionary to separate chains for each line of communication
    // for sent messages
    this.sending_chain = {};
    // dictionary to separate chains for each line of communication 
    // for receivedmessages
    this.receiving_chain = {};
    // dictionary to hold rootKey for HDFK, currently not used
    this.root_chain = {};
    // dictionary for the username to number of messages sent by that user
    this.Ns = {};
    // dictionary for the username to number of messages received from a user
    this.Nr = {};
    // dictionary to check received messages out of order
    this.receive_num = {};
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
    // call the EG method to create a key pair
    const EGKeyPair = await generateEG();
    if (!EGKeyPair) {
        throw ("generateEG: invalid key pair created");
    }
    // fill in the certificate fields and store the keypair
    // for use in other methods
    certificate.username = username;
    certificate.pub = EGKeyPair.pub;
    this.EGKeyPair = EGKeyPair;

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
    // verify the signature matches the certificate given
    const result = await verifyWithECDSA(this.caPublicKey, JSON.stringify(certificate), signature);
    if (result) {
        // if valid, store the certificate in a dictionary keyed by username
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

/*
Our current implementation does not use the double ratchet chaining
functionality as described in the Signal spec for multiple reasons.
This basically means that nowhere in our code do we implement the
HKDF functionality that is needed in the double ratchet algorithm.
Instead, we substitute that by acting as though new messages are always
a new connection, thereby creating a new DH key every time a message is sent
and received. The reasons we cannot follow the Signal spec are:
Firstly, we do not have access to a "shared key" (SK) as described in
the Signal spec. It is supposed to be provided by some outside server
and we were not made aware of that being available anywhere.
Secondly, if we try to create our own shared key, then we run into the 
following problems:
    a) we would have to pass the secret key in the header to the 
    receive message function, which is inherently unsafe
    and
    b) even if we do pass in the secret key to the header, decrypting the
    message was extremely complicated due to the uncertainty of the return
    array type in the HKDF function
We have left our attempts at using HKDF commented in our send and receive
message functions, but running the test cases with the commented code 
would cause multiple errors and is not advised.
 */
async sendMessage(name, plaintext) {
    const iv = genRandomSalt();
    // separate IV for government cipher
    const govIV = genRandomSalt();
    let DHKey = {};

    // create a number of messages sent map for each user
    if (!this.Ns.hasOwnProperty(name)) {
        this.Ns[name] = 0;
    }

    // create a basic header with known variables
    const header = {
        "vGov": this.EGKeyPair.pub,
        "ivGov": govIV,
        "receiver_iv": iv,
        "msg_num": this.Ns[name],
    };

    if (!this.conns.hasOwnProperty(name)) { 
        // if there hasn't been previous communication
        // setup the session by generating the necessary double ratchet keys according to the Signal spec
        // use X3DH to agree on shared secret key - currently impossible to do

        // this is commented because KDF chaining doesn't work
        // this.conns[name] = true;
        // compute the DH key from our secret key and the other user's public key
        DHKey = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
        if (!DHKey) {
            throw ("computeDH: Invalid key!");
        }

        // run X3DH to create shared key
        // starts chain(s)
        // const tmp_key = await HMACtoHMACKey(this.EGKeyPair.sec, govEncryptionDataStr);
        // if (!tmp_key) {
        //     throw ("HMACtoHMACKey: Invalid key!");
        // }

        // const x = await HKDF(DHKey, this.govPublicKey, "first-time");
        // if (!this.root_chain[name] || !this.sending_chain[name]) {
        //     throw ("HKDF: Invalid key!");
        // }

        // generate a new ratchet key pair (assuming DH key)
        // feed DH output to root KDF along with current root key
        // HKDF outputs new root key (store as secret key) and sending chain key (store in sending chain)
    }

    // let msg_key;
    // [this.sending_chain[name], msg_key] = await HKDF(this.root_chain[name], this.sending_chain[name]);
    // if (!this.sending_chain[name] || !msg_key) {
    //     throw ("HKDF: Invalid key!");
    // }

    // apply "symmetric-key ratchet step" to current sending chain key
    // result is new message key
    // new chain key stored, message key and old chain key deleted

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

    // govDecrypt calls decrypt twice, once to decrypt the original AESKey through HKDF
    // and the second for the the actual ciphertext decryption
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

    // increment the number of messages sent to user
    this.Ns[name]++;

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
        // use X3DH to agree on shared secret key
        
        // this is commented because KDF chaining doesn't work
        // this.conns[name] = true;

        //if (!this.Nr.hasOwnProperty(name)) {
        //    this.Nr[name] = 0;
        //}

        if (!this.receive_num.hasOwnProperty(name)) {
            this.receive_num[name] = {};
        }

        const temp = header.msg_num

        // could optimize by bounding the message numbers that need to be tracked,
        // where any message lower than the threshold gets auto-rejected
        // implementing this would likely obfuscate the code however, and won't matter 
        if (!this.receive_num[name].hasOwnProperty(temp)) {
            this.receive_num[name][temp] = true;
        }
        else {
            throw ("Message replay attack foiled");
        }

        DHKey = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
        if (!DHKey) {
            throw ("computeDH: Invalid key!");
        }

        // tmp_key = await HMACtoHMACKey(this.EGKeyPair.sec, govEncryptionDataStr);
        // if (!tmp_key) {
        //     throw ("HMACtoHMACKey: Invalid key!");
        // }

        // [this.root_chain[name], this.receiving_chain[name]] = await HKDF(tmp_key, DHKey);

        // if (!this.root_chain[name] || !this.receiving_chain[name]) {
        //     throw ("HKDF: Invalid key!");
        // }
        
    }

    // have to derive new receiving chain key when we receive a new message
    // let msg_key;
    // [this.receiving_chain[name], msg_key] = await HKDF(this.root_chain[name], this.receiving_chain[name]);
    // if (!this.receiving_chain[name] || !msg_key) {
    //     throw ("HKDF: Invalid key!");
    // }

    // convert the HMAC output of the DH key to an AES key for encryption
    const AESKey = await HMACtoAESKey(DHKey, govEncryptionDataStr);
    if (!AESKey) {
        throw ("HMACtoAESKey: Invalid key!");
    }

    // decrypt the ciphertext and return plaintext
    const plaintext = await decryptWithGCM(AESKey, ciphertext, header.receiver_iv, JSON.stringify(header));
    if (plaintext) {
        // increment the number of messages received
        this.Nr[name]++;
        return byteArrayToString(plaintext);
    } else {
        throw("decryptWithGCM: Invalid plaintext!");
    }
}
};