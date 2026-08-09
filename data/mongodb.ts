/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME due to non-existing type definitions for MarsDB
import * as MarsDB from 'marsdb'

// A selector carrying $where is a selector carrying code, and every caller here can say what it
// wants with plain fields. Refusing it at the collection means no caller can reintroduce it.
const carriesCode = (selector: unknown): boolean => {
  if (Array.isArray(selector)) {
    return selector.some(carriesCode)
  }
  if (selector !== null && typeof selector === 'object') {
    return Object.entries(selector as Record<string, unknown>).some(([key, value]) => key === '$where' || carriesCode(value))
  }
  return false
}

const refuseCode = (collection: any) => {
  for (const method of ['find', 'findOne', 'update', 'remove', 'count']) {
    const original = collection[method].bind(collection)
    collection[method] = (selector: unknown, ...rest: unknown[]) => {
      if (carriesCode(selector)) {
        return Promise.reject(new Error('Query selectors must not carry code'))
      }
      return original(selector, ...rest)
    }
  }
  return collection
}

export const reviewsCollection = refuseCode(new MarsDB.Collection('posts'))
export const ordersCollection = refuseCode(new MarsDB.Collection('orders'))
