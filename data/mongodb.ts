/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME due to non-existing type definitions for MarsDB
import * as MarsDB from 'marsdb'

/* Every selector reaching MarsDB passes through here. Two review lookups legitimately use a
   $where clause, and $where is executable JavaScript, so the only form the shop ever needs is the
   one it builds itself: a comparison against a plain number. Anything else - a string operand, a
   call, a second statement smuggled in through an id - is refused at this boundary instead of
   relying on each caller to remember to coerce its own input. The refusal is a rejected promise,
   which the callers already surface as a 400. */
const SAFE_WHERE = /^this\.[A-Za-z_][A-Za-z0-9_]* == \d+$/

class UnsafeSelectorError extends Error {}

const assertSafeSelector = (selector: unknown): void => {
  if (selector === null || typeof selector !== 'object') {
    return
  }
  for (const [key, value] of Object.entries(selector as Record<string, unknown>)) {
    if (key === '$where') {
      if (typeof value !== 'string' || !SAFE_WHERE.test(value)) {
        throw new UnsafeSelectorError('Refused a $where clause that is not a plain numeric comparison')
      }
    } else if (value !== null && typeof value === 'object') {
      assertSafeSelector(value)
    }
  }
}

const guardSelectors = (collection: any) => {
  for (const method of ['find', 'findOne', 'update', 'remove', 'count']) {
    const original = collection[method].bind(collection)
    collection[method] = (selector?: unknown, ...rest: unknown[]) => {
      try {
        assertSafeSelector(selector)
      } catch (error) {
        return Promise.reject(error)
      }
      return original(selector, ...rest)
    }
  }
  return collection
}

export const reviewsCollection = guardSelectors(new MarsDB.Collection('posts'))
export const ordersCollection = guardSelectors(new MarsDB.Collection('orders'))
