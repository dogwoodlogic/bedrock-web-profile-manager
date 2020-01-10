/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import bcrypt from 'bcryptjs';
import {AccountService} from 'bedrock-web-account';
import jsonpatch from 'fast-json-patch';
import {CapabilityDelegation} from 'ocapld';
import {ControllerKey, KmsClient} from 'webkms-client';
import {EdvClient} from 'edv-client';
import jsigs from 'jsonld-signatures';
import EdvClientCache from './EdvClientCache.js';
import {generateDidDoc} from './did.js';
import {LDKeyPair} from 'crypto-ld';

const {SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {Ed25519Signature2018} = suites;

const DEFAULT_HEADERS = {Accept: 'application/ld+json, application/json'};

export default class ProfileManager {
  /**
   * Creates a new instance of a ProfileManager and attaches it to the given
   * session instance. This ProfileManager will track changes to the given
   * session, creating and/or caching account and profile edvs as needed.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.session - A `bedrock-web-session` session instance.
   * @param {string} options.kmsModule - The KMS module to use to generate keys.
   * @param {string} options.kmsBaseUrl - The base URL for the KMS service,
   *   used to generate keys.
   * @param {string} options.recoveryHost - The recovery host application to
   *   use for keystore configs.
   *
   * @returns {ProfileManager} - The new instance.
   */
  constructor({kmsModule, kmsBaseUrl, recoveryHost}) {
    if(typeof kmsModule !== 'string') {
      throw new TypeError('"kmsModule" must be a string.');
    }
    if(typeof kmsBaseUrl !== 'string') {
      throw new TypeError('"kmsBaseUrl" must be a string.');
    }
    this.session = null;
    this.accountId = null;
    this.controllerKey = null;
    this.edvClientCache = new EdvClientCache();
    this.kmsModule = kmsModule;
    this.kmsBaseUrl = kmsBaseUrl;
    if(recoveryHost) {
      this.recoveryHost = recoveryHost.startsWith('https://') ?
        recoveryHost : `https://${recoveryHost}`;
    }
  }

  /**
   * Attaches this instance to the given session. This ProfileManager will
   * track changes to the given session, creating and/or caching account and
   * profile edvs as needed.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.session - A `bedrock-web-session` session instance.
   *
   * @returns {Promise} - Resolves once the operation completes.
   */
  async setSession({session}) {
    if(this.session) {
      throw new Error('Already attached to a session.');
    }
    this.session = session;
    this.removeListener = session.on(
      'change', event => this._sessionChanged(event));
    // emulate initial session change event
    await this._sessionChanged({newData: session.data});
  }

  async getAccountEdv() {
    return this.edvClientCache.get('primary');
  }

  async getProfileEdv({profileId}) {
    const id = `profile.${profileId}`;
    let edvClient = await this.edvClientCache.get(id);
    if(edvClient) {
      return edvClient;
    }

    const accountEdv = await this.getAccountEdv();
    const {controllerKey: invocationSigner} = this;
    const [doc] = await accountEdv.find({
      equals: {'content.id': profileId},
      invocationSigner
    });
    if(!doc) {
      // no such profile stored with the given account
      return null;
    }

    // get the profile edv
    const {content: profile} = doc;
    const config = await EdvClient.getConfig({id: profile.edv});
    const [keyAgreementKey, hmac] = await Promise.all([
      this.controllerKey.getKeyAgreementKey(
        {id: config.keyAgreementKey.id, type: config.keyAgreementKey.type}),
      this.controllerKey.getHmac({id: config.hmac.id, type: config.hmac.type})
    ]);
    edvClient = new EdvClient(
      {id: config.id, keyResolver, keyAgreementKey, hmac});
    await this.edvClientCache.set(id, edvClient);
    return edvClient;
  }

  async createProfile({type, content}) {
    const keyType = 'Ed25519VerificationKey2018';
    // generate an invocation key and a DID Document for the profile
    // FIXME: add support for key generation via webkms-client, invoke key
    // is currently discarded
    const invokeKey = await LDKeyPair.generate({type: keyType});
    const didDoc = await generateDidDoc({invokeKey, keyType});
    const {id: did} = didDoc;

    // TODO: support making the profile edv controlled by the profile
    // instead

    // get primary edv and create an account controlled edv for
    // the new profile
    const [accountEdv, profileEdv] = await Promise.all([
      this.getAccountEdv(),
      this._createEdv()
    ]);

    // insert a profile document into the primary edv
    let profileType = 'Profile';
    if(type) {
      profileType = [profileType, type];
    }
    const doc = {
      content: {
        ...content,
        id: did,
        type: profileType,
        // TODO: might need this to be the specific document -- or a zcap
        edv: profileEdv.id
      }
    };
    const {controllerKey: invocationSigner} = this;
    await accountEdv.insert({doc, invocationSigner});

    // cache the profile edv
    await this.edvClientCache.set(`profile.${did}`, profileEdv);

    return doc;
  }

  // TODO: implement adding an existing profile to an account

  async getProfile({profileId}) {
    const edvClient = await this.getAccountEdv();
    if(!edvClient) {
      return null;
    }
    const {controllerKey: invocationSigner} = this;
    const [doc = null] = await edvClient.find({
      equals: {'content.id': profileId},
      invocationSigner
    });
    return doc;
  }

  async getProfiles({type} = {}) {
    const edvClient = await this.getAccountEdv();
    if(!edvClient) {
      return [];
    }
    const {controllerKey: invocationSigner} = this;
    const profileDocs = await edvClient.find({
      equals: {'content.type': 'Profile'},
      invocationSigner
    });
    if(!type) {
      return profileDocs;
    }
    return profileDocs.filter(({content}) => content.type.includes(type));
  }

  async delegateCapability({profileId, request}) {
    const {
      invocationTarget, invoker, referenceId, allowedAction, caveat
    } = request;
    if(!(invocationTarget && typeof invocationTarget === 'object' &&
      invocationTarget.type)) {
      throw new TypeError(
        '"invocationTarget" must be an object that includes a "type".');
    }

    const edvClient = await this.getProfileEdv({profileId});

    // TODO: to reduce correlation between the account and multiple profiles,
    // consider generating a unique controller key per profile DID, but
    // consider the additional overhead for password replacement
    const {controllerKey} = this;
    const signer = controllerKey;

    let zcap = {
      '@context': SECURITY_CONTEXT_V2_URL,
      // use 128-bit random multibase encoded value
      id: `urn:zcap:${await EdvClient.generateId()}`,
      invoker
    };
    if(referenceId) {
      zcap.referenceId = referenceId;
    }
    if(allowedAction) {
      zcap.allowedAction = allowedAction;
    }
    if(caveat) {
      zcap.caveat = caveat;
    }
    let {parentCapability} = request;
    const {id: target, type: targetType} = invocationTarget;
    if(targetType === 'Ed25519VerificationKey2018') {
      if(!target) {
        throw new TypeError(
          '"invocationTarget.id" must be set for Web KMS capabilities.');
      }
      // TODO: fetch `target` from a key mapping document in the profile's
      // edv to get public key ID to set as `referenceId`
      zcap.invocationTarget = {
        id: target,
        type: targetType,
        // TODO: put public key ID here
        //referenceId:
      };
      zcap.parentCapability = parentCapability || target;
      zcap = await _delegate({zcap, signer});

      await controllerKey.kmsClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else if(targetType === 'urn:edv:document') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        // use 128-bit random multibase encoded value
        const docId = await EdvClient.generateId();
        zcap.invocationTarget.id = `${edvClient.id}/documents/${docId}`;
        // insert empty doc to establish self as a recipient
        const doc = {
          id: docId,
          content: {}
        };
        const {controllerKey: invocationSigner} = this;
        // TODO: this is not clean; zcap query needs work! ... another
        // option is to get a `keyAgreement` verification method from
        // the controller of the `invoker`
        const recipients = [{
          header: {
            kid: edvClient.keyAgreementKey.id,
            alg: 'ECDH-ES+A256KW'
          }
        }];
        if(invocationTarget.recipient) {
          recipients.push(invocationTarget.recipient);
        }
        await edvClient.insert({doc, recipients, invocationSigner});
      }
      if(!parentCapability) {
        const idx = zcap.invocationTarget.id.lastIndexOf('/');
        const docId = zcap.invocationTarget.id.substr(idx + 1);
        parentCapability = `${edvClient.id}/zcaps/documents/${docId}`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});

      // enable zcap via edv client
      await edvClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else if(targetType === 'urn:edv:documents') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        // TODO: note that only the recipient of the zcap will be able
        // to read the documents it writes -- as no recipient is specified
        // here ... could add this to the zcap as a special caveat that
        // requires the recipient always be present for every document written
        zcap.invocationTarget.id = `${edvClient.id}/documents`;
      }
      if(!parentCapability) {
        parentCapability = `${edvClient.id}/zcaps/documents`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});

      // enable zcap via edv client
      await edvClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else if(targetType === 'urn:edv:authorizations') {
      zcap.invocationTarget = {
        id: target,
        type: targetType
      };

      if(target) {
        // TODO: handle case where an existing target is requested
      } else {
        zcap.invocationTarget.id = `${edvClient.id}/authorizations`;
      }
      if(!parentCapability) {
        parentCapability = `${edvClient.id}/zcaps/authorizations`;
      }
      zcap.parentCapability = parentCapability;
      zcap = await _delegate({zcap, signer});

      // enable zcap via edv client
      await edvClient.enableCapability(
        {capabilityToEnable: zcap, invocationSigner: signer});
    } else {
      throw new Error(`Unsupported invocation target type "${targetType}".`);
    }
    return zcap;
  }

  async _sessionChanged({authentication, newData}) {
    const {account = {}} = newData;
    const {id: newAccountId = null} = account;

    // clear cache
    if(this.accountId && this.accountId !== newAccountId) {
      await ControllerKey.clearCache({handle: this.accountId});
      await this.edvClientCache.clear();
    }

    // update state
    const accountId = this.accountId = newAccountId;
    this.controllerKey = null;

    if(!(authentication || newData.account)) {
      // no account in session, return
      return;
    }

    // cache account controller key
    const {secret} = (authentication || {});
    const kmsClient = new KmsClient();
    this.controllerKey = await (secret ?
      _getControllerKeyFromSecret({secret, accountId, kmsClient}) :
      ControllerKey.fromCache({handle: accountId, kmsClient}));
    if(this.controllerKey === null) {
      // could not load from cache and no `secret`, so cannot load edv
      return;
    }

    // ensure primary keystore exists for controller key
    await this._ensureKeystore({accountId});

    // ensure the account's primary edv exists and cache it
    const edvClient = await this._ensureEdv();
    await this.edvClientCache.set('primary', edvClient);
  }

  async _createEdv({referenceId} = {}) {
    // create KAK and HMAC keys for edv config
    const {controllerKey, kmsModule} = this;
    const [keyAgreementKey, hmac] = await Promise.all([
      controllerKey.generateKey({type: 'keyAgreement', kmsModule}),
      controllerKey.generateKey({type: 'hmac', kmsModule})
    ]);

    // create edv
    let config = {
      sequence: 0,
      controller: controllerKey.handle,
      // TODO: add `invoker` and `delegator` using controllerKey.id *or*, if
      // this is a profile's edv, the profile ID
      invoker: controllerKey.id,
      delegator: controllerKey.id,
      keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
      hmac: {id: hmac.id, type: hmac.type}
    };
    if(referenceId) {
      config.referenceId = referenceId;
    }
    config = await EdvClient.createEdv({config});
    return new EdvClient(
      {id: config.id, keyResolver, keyAgreementKey, hmac});
  }

  async _ensureEdv() {
    const {controllerKey} = this;
    const config = await EdvClient.findConfig(
      {controller: controllerKey.handle, referenceId: 'primary'});
    if(config === null) {
      return await this._createEdv({referenceId: 'primary'});
    }
    const [keyAgreementKey, hmac] = await Promise.all([
      controllerKey.getKeyAgreementKey(
        {id: config.keyAgreementKey.id, type: config.keyAgreementKey.type}),
      controllerKey.getHmac({id: config.hmac.id, type: config.hmac.type})
    ]);
    return new EdvClient(
      {id: config.id, keyResolver, keyAgreementKey, hmac});
  }

  async _createKeystore({referenceId} = {}) {
    const {controllerKey, recoveryHost} = this;

    // create keystore
    const config = {
      sequence: 0,
      controller: controllerKey.id,
      invoker: controllerKey.id,
      delegator: controllerKey.id
    };
    if(recoveryHost) {
      config.invoker = [config.invoker, recoveryHost];
    }
    if(referenceId) {
      config.referenceId = referenceId;
    }
    return await KmsClient.createKeystore({
      url: `${this.kmsBaseUrl}/keystores`,
      config
    });
  }

  async _ensureKeystore({accountId}) {
    const {controllerKey} = this;

    // see if there is an existing keystore for the account
    const service = new AccountService();
    const {account: {keystore}} = await service.get({id: accountId});
    if(keystore) {
      // keystore exists, get config and check against controller key
      let config = await KmsClient.getKeystore({id: keystore});
      const {controller} = config;
      if(controller !== controllerKey.id) {
        // keystore does NOT match; perform recovery
        config = await this._recoverKeystore({id: keystore});
        // TODO: handle future case where user has not authorized the
        // host application to perform recovery
      }
      controllerKey.kmsClient.keystore = config.id;
      return config;
    }

    // if there is no existing keystore...
    let config = await KmsClient.findKeystore({
      url: `${this.kmsBaseUrl}/keystores`,
      controller: controllerKey.id,
      referenceId: 'primary'
    });
    if(config === null) {
      config = await this._createKeystore({referenceId: 'primary'});
    }
    if(config === null) {
      return null;
    }
    controllerKey.kmsClient.keystore = config.id;

    await this._addKeystoreToAccount({accountId, keystoreId: config.id});

    return config;
  }

  async _addKeystoreToAccount({accountId, keystoreId}) {
    const service = new AccountService();
    while(true) {
      const {account, meta} = await service.get({id: accountId});
      if(account.keystore === keystoreId) {
        break;
      }

      const {sequence} = meta;
      const observer = jsonpatch.observe(account);
      const patch = jsonpatch.generate(observer);
      account.keystore = keystoreId;
      jsonpatch.unobserve(account, observer);
      try {
        await service.update({id: accountId, sequence, patch});
        break;
      } catch(e) {
        // if e has a conflict response try again, otherwise throw error
        const {response = {}} = e;
        if(response.status !== 409) {
          throw e;
        }
      }
    }
  }

  async _recoverKeystore({id}) {
    // FIXME: this needs to be posted to a different endpoint that is
    // able to authenticate the user and ensure that the controller being
    // updated was under the control of the user's account
    const {controllerKey} = this;
    const url = `${id}/recover`;
    const response = await axios.post(url, {
      '@context': 'https://w3id.org/security/v2',
      controller: controllerKey.id
    }, {headers: DEFAULT_HEADERS});
    const keystoreConfig = response.data;

    // clear edv client cache so new instances will use new controller key
    this.edvClientCache.clear();

    // update account edv
    const edvClient = await this._ensureEdv();
    await this.edvClientCache.set('primary', edvClient);
    const config = await EdvClient.getConfig({id: edvClient.id});
    config.sequence++;
    config.invoker = config.delegator = controllerKey.id;
    await EdvClient.updateConfig({id: edvClient.id, config});

    // TODO: updating profile edvs should not be required once profile
    // edvs properly use the profile's keys for invoker/delegator
    // instead of the account's controller key

    // update all profile edvs
    const profiles = await this.getProfiles();
    await Promise.all(profiles.map(async ({content: profile}) => {
      const config = await EdvClient.getConfig({id: profile.edv});
      config.sequence++;
      config.invoker = config.delegator = controllerKey.id;
      await EdvClient.updateConfig({id: profile.edv, config});
    }));

    return keystoreConfig;
  }
}

async function _delegate({zcap, signer}) {
  // attach capability delegation proof
  return sign(zcap, {
    // TODO: map `signer.type` to signature suite
    suite: new Ed25519Signature2018({
      signer,
      verificationMethod: signer.id
    }),
    purpose: new CapabilityDelegation({
      capabilityChain: [zcap.parentCapability]
    }),
    compactProof: false
  });
}

// helper that mixes a user generated secret and a server-side seed
async function _getControllerKeyFromSecret({secret, accountId, kmsClient}) {
  // get `controllerKeySalt` from account; it will be mixed with the user
  // secret so that the controller key can't be created without *both* a user
  // supplied secret and a server side secret salt that can't be accessed
  // unless the user has authenticated with the server (which may include
  // two-factor auth, etc.)
  const service = new AccountService();
  const {account: {controllerKeySalt}} = await service.get({id: accountId});
  if(!controllerKeySalt) {
    throw new Error(
      'Could not generate controller key for account; ' +
      '"controllerKeySalt" not found.');
  }

  // hash secret with controller key salt
  secret = await bcrypt.hash(secret, controllerKeySalt);
  return ControllerKey.fromSecret({secret, handle: accountId, kmsClient});
}

// FIXME: make more restrictive, support `did:key` and `did:v1`
async function keyResolver({id}) {
  const response = await axios.get(id, {
    headers: DEFAULT_HEADERS
  });
  return response.data;
}
