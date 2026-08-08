/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomUUID } from 'node:crypto'

type Document = Record<string, any> & { _id: string }
type Selector = Record<string, unknown>
type Update = {
  $set?: Record<string, unknown>
  $inc?: Record<string, number>
}

export interface UpdateResult<T extends Document> {
  modified: number
  original: T[]
}

/* MarsDB evaluates JavaScript supplied through query operators such as $where
   and has no patched release. The application only needs a small, in-process
   document store, so keep that surface deliberately limited to exact matches,
   one parsed legacy numeric lookup, and the two update operators used by the
   review and order routes. No query text is ever evaluated. */
export class MemoryCollection<T extends Document = Document> {
  private readonly documents: T[] = []

  async insert (document: Omit<T, '_id'> & Partial<Pick<T, '_id'>>): Promise<T> {
    const stored = structuredClone({ ...document, _id: document._id ?? randomUUID() }) as T
    this.documents.push(stored)
    return structuredClone(stored)
  }

  async find (selector: Selector = {}): Promise<T[]> {
    const normalizedSelector = this.normalizeSelector(selector)
    return this.documents.filter(document => this.matches(document, normalizedSelector)).map(document => structuredClone(document))
  }

  async findOne (selector: Selector): Promise<T | undefined> {
    const normalizedSelector = this.normalizeSelector(selector)
    const document = this.documents.find(document => this.matches(document, normalizedSelector))
    return document === undefined ? undefined : structuredClone(document)
  }

  async update (selector: Selector, update: Update): Promise<UpdateResult<T>> {
    const normalizedSelector = this.normalizeSelector(selector)
    this.assertSafeUpdate(update)

    const document = this.documents.find(document => this.matches(document, normalizedSelector))
    if (document === undefined) {
      return { modified: 0, original: [] }
    }

    const original = structuredClone(document)
    if (update.$set !== undefined) {
      Object.assign(document, structuredClone(update.$set))
    }
    if (update.$inc !== undefined) {
      for (const [field, increment] of Object.entries(update.$inc)) {
        const current = document[field]
        if (typeof current !== 'number') {
          throw new TypeError(`Cannot increment non-numeric field: ${field}`)
        }
        ;(document as Document)[field] = current + increment
      }
    }

    return { modified: 1, original: [original] }
  }

  async count (selector: Selector = {}): Promise<number> {
    return (await this.find(selector)).length
  }

  private matches (document: T, selector: Selector): boolean {
    return Object.entries(selector).every(([field, expected]) => document[field] === expected)
  }

  private normalizeSelector (selector: Selector): Selector {
    if (selector === null || Array.isArray(selector) || typeof selector !== 'object') {
      throw new TypeError('Selector must be an object')
    }
    const entries = Object.entries(selector)
    if (entries.length === 1 && entries[0][0] === '$where' && typeof entries[0][1] === 'string') {
      const legacyProductLookup = /^this\.product == (-?\d+(?:\.\d+)?)$/.exec(entries[0][1])
      if (legacyProductLookup !== null) {
        const product = Number(legacyProductLookup[1])
        if (Number.isFinite(product)) return { product }
      }
    }
    for (const [field, value] of Object.entries(selector)) {
      if (field.startsWith('$') || (typeof value === 'object' && value !== null)) {
        throw new TypeError('Only exact-match selectors are supported')
      }
    }
    return selector
  }

  private assertSafeUpdate (update: Update): void {
    const operators = Object.keys(update)
    if (operators.length === 0 || operators.some(operator => operator !== '$set' && operator !== '$inc')) {
      throw new TypeError('Unsupported update')
    }
    if (update.$inc !== undefined && Object.values(update.$inc).some(increment => !Number.isFinite(increment))) {
      throw new TypeError('Increment must be finite')
    }
  }
}

// These stores contain the existing heterogeneous review/order shapes. Route
// handlers continue to own their response types, as they did with MarsDB.
export const reviewsCollection = new MemoryCollection<any>()
export const ordersCollection = new MemoryCollection<any>()
