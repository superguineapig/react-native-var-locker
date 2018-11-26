// @flow
import { Map } from 'immutable';
import { RSAKeychain } from 'react-native-rsa-native';

/**
 * namespace prefix for device keychain to prevent interfering with existing
 * keypairs
 * @private
 */
const PFX_TAG = 'com.github.superguineapig';

// utils
const _keyCheck = (id: string) => ((Boolean(id) && typeof id === 'string' && !/\s/.test(id)));
const _getInternalId = (id: string) => (`${PFX_TAG}+${id}`);

/**
 * backing immutable map
 * @private
 */
let _staticTagMap: Map<string, Map<string, string>> = Map();

/**
 * Try to remove an RSA keypair from the device keychain
 * @param {string} id - friendly id (tag) to identify the keypair internally
 * @throws {Error} if key is null or empty
 * @throws {Error} if keys already disposed for id
 * @static
 */
function _disposeKeysForId(id: string): Promise<void> {
  if (!_keyCheck(id)) {
    throw new Error('key cannot be empty nor contain whitespace');
  }
  return _isIdInDeviceKeychain(id)
    .then(exists => {
      if (!exists) {
        throw new Error(`keys already disposed for id: ${id}`);
      }
      return RSAKeychain.deletePrivateKey(_getInternalId(id))
    })
    .then(() => {
      if (_staticTagMap.has(id)) {
        _staticTagMap = _staticTagMap.delete(id);
      }
      return;
    });
}

/**
 * constructs a convenience SecureMap instance bound to a particular tag(id)
 * @param {string} id - friendly, unique id used to identify the map instance
 * @throws {Error} if key is null or empty
 * @throws {Error} if something on the native side blows up
 * @static
 */
function _getMapForId(id: string): Promise<_SecureMap> {
  return new Promise(resolve => {
    resolve(_keyCheck(id));
  })
  .then(keyOk => {
    if (keyOk) {
      return _isIdInDeviceKeychain(id);
    }
    throw new Error('id must be non-empty string');
  })
  .then(hasKeys => {
    if (!hasKeys) {
      return RSAKeychain.generate(_getInternalId(id));
    }
    return true;
  })
  .then(() => {
    return _staticTagMap.has(id);
  })
  .then(hasMap => {
    if (!hasMap) {
      _staticTagMap = _staticTagMap.set(id, Map());
    }
    return true;
  })
  .then(() => {
    return new _SecureMap(id);
  });
}

/**
 * Check device's keychain for existence of RSA keypair of id
 * @param {string} id - the friendly id of a keypair
 */
function _isIdInDeviceKeychain(id: string): Promise<boolean> {
  return RSAKeychain.getPublicKey(_getInternalId(id))
    .then(pub => {
      return pub != null;
    });
}


/**
 * @summary immutable map-like structure that uses device-local RSA keypair to store
 * encrypted values in memory
 *
 * @classdesc although this uses native keychains, bad guys with access
 * to the device and debugging tools can still get the secrets.
 * This is meant to be used at runtime for temporary storage of
 * sensitive values; you can pass around the map keys in places where
 * the raw values themselves would expose risk (logging, redux actions, etc.)
 * The map itself only stores encrypted values, so a memory dump or object
 * serialization of the backing map (console/debug logs, etc.)
 * won't expose the raw unencrypted value.
 * This offers a little bit of extra protection against common leaks.
 * Map keys are transient and volatile and should not be stored off-line.
 *
 * Never create _SecureMap manually. Always use _getMapForId to get an instance.
 *
 * @class
 * @private
 */
class _SecureMap {
  /**
   * @private
   */
  #fullTag = '';

  /**
   * @private
   */
  #tag = '';

  constructor(id: string) {
      this.#tag = id;
      this.#fullTag = _getInternalId(id);
  }

  /**
   * The internal identifier for the keypair used with this map
   * @type {string}
   */
  get fullyQualifiedTag(): string {
    return this.#fullTag;
  }

  /**
   * Number of entries in the secure map
   * @type {number}
   */
  get size(): number {
    if (!_staticTagMap.has(this.#tag)) {
      throw new Error(`backing map for '${this.#tag}' does not exist/may have been disposed`);
    }
    return _staticTagMap.get(this.#tag, {size:0}).size;
  }

  /**
   * The friendly identifier for this map, used in instance creation
   * @type {string}
   */
  get tag(): string {
    return this.#tag;
  }

  /**
   * Clears the underlying map for this tag, removing any stored KVPs
   * @returns {_SecureMap} this object instance for chaining
   * @throws {Error} If backing map and keypair have been disposed
   */
  empty(): _SecureMap {
    const tgt = _staticTagMap.get(this.#tag);
    if (!tgt) {
      throw new Error(`backing map for '${this.#tag}' does not exist/may have been disposed`);
    }
    // using immutable api to allow for most efficient object reference handling
    _staticTagMap = _staticTagMap.set(this.#tag, tgt.clear());
    return this;
  }

  /**
   * Checks if a value is stored for the given key
   * @param {string} key - Key in map
   * @returns {boolean} status of existence of 'key' in map
   * @throws {Error} If backing map and keypair have been disposed
   */
  hasItem(key: string): boolean {
    if (!_staticTagMap.has(this.#tag)) {
      throw new Error(`backing map for '${this.#tag}' does not exist/may have been disposed`);
    }
    return _staticTagMap.hasIn([this.#tag, key]);
  }

  /**
   * Retrieves encrypted value from backing map, and returns decrypted value
   * @param {string} key - Key in map associated with the desired value
   * @param {boolean} [remove=true] - flag indicating if value should be
   *  removed from the map after retrieval.
   * @returns {Promise<string>} A resolved promise with the decrypted value
   * @throws {Error} If 'key' is null or empty
   * @throws {Error} If backing map and keypair have been disposed
   * @throws {Error} If 'key' is not in backing map
   */
  retrieveItem(key: string, remove?: boolean = true): Promise<string> {
    if (!_keyCheck(key)) {
      throw new Error('key cannot be empty nor contain whitespace');
    }
    if (!_staticTagMap.has(this.#tag)) {
      throw new Error(`backing map for '${this.#tag}' does not exist/may have been disposed`);
    }
    if (!_staticTagMap.hasIn([this.#tag, key])) {
      throw new Error(`key: '${key}' does not exist in map`);
    }
    return RSAKeychain.decrypt(
      _staticTagMap.getIn([this.#tag, key], ''),
      this.#fullTag
    )
    .then(decVal => {
      if (remove) {
        _staticTagMap = _staticTagMap.deleteIn([this.#tag, key]);
      }
      return decVal;
    });
  }

  /**
   * Encrypts 'value' and associates it with the provided 'key'.
   * Only the encrypted value is stored in mempry.
   * @param {string} key - Key to associate with the encrypted value
   * @param {string} value - The raw/unencrypted value to securely store
   * @returns {Promise<string>} A resolved promise with this instance
   * @throws {Error} If 'key' is null or empty
   * @throws {Error} If backing map and keypair have been disposed
   * @throws {Error} If 'key' is already in backing map
   */
  storeItem(key: string, value: string): Promise<_SecureMap> {
    if (!_keyCheck(key)) {
      throw new Error('key cannot be empty nor contain whitespace');
    }
    if (!_staticTagMap.has(this.#tag)) {
      throw new Error(`backing map for '${this.#tag}' does not exist/may have been disposed`);
    }
    if (_staticTagMap.hasIn([this.#tag, key])) {
      throw new Error(`key: '${key}' already in map`);
    }
    return RSAKeychain.encrypt(
      value,
      this.#fullTag
    )
    .then(encVal => {
      _staticTagMap = _staticTagMap.setIn(
        [this.#tag, key],
        encVal
      );
      return this;
    });
  }

};

/********************************* EXPORTS ************************************/

export type SecureMap = _SecureMap;

/**
 * 'Static' utility class used to create and dispose SecureMap instances.
 * SecureMap is an interface type of a 'private' class that is NOT to be
 * instantiated by itself (using new, or a constructor-like syntax)
 * @namespace
 * @borrows _disposeKeysForId as disposeKeysForId
 * @borrows _getMapForId as getMapForId
 * @borrows _isIdInDeviceKeychain as isIdInDeviceKeychain
 */
export const SecureMapFactory = {
  disposeKeysForId: _disposeKeysForId,
  getMapForId: (id: string): Promise<SecureMap> => {
    return _getMapForId(id);
  },
  isIdInDeviceKeychain: _isIdInDeviceKeychain
};
