/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

export default class EdvClientCache {
  constructor() {
    this.cache = new Map();
  }

  async set(id, client) {
    client.ensureIndex({attribute: 'content.id', unique: true});
    client.ensureIndex({attribute: 'content.type'});
    this.cache.set(id, client);
    return client;
  }

  async get(id) {
    return this.cache.get(id) || null;
  }

  async delete(id) {
    return this.cache.delete(id);
  }

  async clear() {
    this.cache.clear();
  }
}
