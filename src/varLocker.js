// @flow
import { SecureMapFactory } from './secureMap';
import type { SecureMap } from './secureMap';

// TODO: pull this out of this file; make configurable externally
const LOCKER_TAG = 'locker';

// @returns {string} strings of chars [a-z] at length len
export function generateKeyString(len: number): string {
  if (isNaN(len) || len < 4 || len > 64) {
    throw new Error('len must be a number between 4 and 64 inclusive');
  }
  // not sure if this makes a perf difference in javascript
  const buffer: Array<string> = Array(len).fill('');
  // char code range 97 - 122
  const gen = () => {
    return Math.floor(Math.random() * 26) + 97;
  };
  for (let i = 0; i < len; i++) {
    buffer[i] = String.fromCharCode(gen());
  }
  return buffer.join('');
}

/**
 * @classdesc Wraps a SecureMap to provide a more limited and secure interface by
 * auto-generating key strings for stored items
 * Like having a pool of encrypted variables at your disposal; a place to put
 * sensitive values without storing the actual values in RAM
 * @class
 */
export class VarLocker {
  #evicted: boolean;
  #store: SecureMap;

  /**
   * Convenience method to get a reference to a VarLocker instance.
   * It is recommended to acquire a non-common locker and evict it
   * when no longer needed
   *
   * @param {boolean} [common=true] - when true the returned instance will proxy
   * to a shared SecureMap; all instances returned by acquire(true) will
   * reference the same SecureMap, and use the same crypto keypair in the
   * device keychain. False forces creation of a new SecureMap with unique crypto keys
   * @returns {Promise<VarLocker>} A resolved promise of a VarLocker instance
   * bound to a SecureMap and its crypto keypair
   * @static
   */
  static acquire(common?: boolean = true): Promise<VarLocker> {
    return SecureMapFactory.getMapForId(common ? LOCKER_TAG : (generateKeyString(4) + Date.now().toString()))
      .then(sm => {
        return new VarLocker(sm);
      });
  }

  constructor(store: SecureMap) {
    this.#evicted = false;
    this.#store = store;
  }

  /**
   * returns the current eviction state of the Locker
   * @type {boolean}
   */
  isEvicted(): Promise<boolean> {
    let p = Promise.resolve(this.#evicted);
    if (!this.#evicted) {
      p = SecureMapFactory.isIdInDeviceKeychain(this.id)
        .then(b => {
          if (!b) {
            this.#evicted = true;
            return true;
          }
          return false;
        })
        .catch(() => {
          this.#evicted = true;
          return true;
        });
    }
    return p;
  }

  /**
   * returns the friendly id used to identify this locker (and backing SecureMap)
   * @type {string}
   */
  get id(): string {
    return this.#store.tag;
  }

  // underlying crypto keypairs are destroyed upon eviction
  // acquiring a locker of id X which has been previously evicted/disposed
  // will result in a new crypto keypair being generated for id X
  evict(): Promise<VarLocker> {
    return SecureMapFactory.disposeKeysForId(this.id)
      .then(() => {
        this.#evicted = true;
        return this;
      });
  }

  /**
   * @param {string} key - the auto generated key for a stored item
   * @returns {boolean} true if key exists and assoc. item is stored in locker
   * @throws {Error} If Locker/SecureMap has been evicted/disposed
   */
  keyInUse(key: string): boolean {
    return this.#store.hasItem(key);
  }

  /**
   * Retrieving an item always removes it from the locker
   * @param {string} key - id of item to retrieve
   * @returns {Promise<string>} resolved promise of the stored item value
   * @throws {Error} If key is poorly formatted
   * @throws {Error} If key not in use (no item)
   * @throws {Error} If Locker/SecureMap has been evicted/disposed
   */
  retrieveItem(key: string): Promise<string> {
    return this.#store.retrieveItem(key, true);
  }

  /**
   * Put a value into a secure locker, and get the key for later retrieval
   * @param {string} item - the value to store (securely)
   * @param {number} [keyLen=6] - may be used to explicitly define the length of
   * the auto-generated key string. MIN(6), MAX(32)
   * @returns {Promise<string>} Resolved promise of the key string associated
   * with the newly stored value
   * @throws {Error} If item is null or empty
   * @throws {Error} If keyLen is out of bounds
   * @throws {Error} If Locker/SecureMap has been evicted/disposed
   */
  storeItem(item: string, keyLen?: number = 6): Promise<string> {
    if (!item) {
      throw new Error('item must be a non-empty string value');
    }
    if ((keyLen < 6) || (keyLen > 32)) {
      throw new Error('keyLen must be between [6, 32] inclusive');
    }
    // ensure no key collisions
    let key = generateKeyString(keyLen);
    while (this.keyInUse(key)) {
      key = generateKeyString(keyLen);
    }
    return this.#store.storeItem(key, item)
      .then(sm => {
        if (sm) {
          return key;
        }
        // should never get to this throw
        throw new Error('unable to store item in locker');
      });
  }

}
