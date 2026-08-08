/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { expect } from 'chai'

import { MemoryCollection } from '../../data/mongodb'

interface TestDocument extends Record<string, any> {
  _id: string
  owner: string
  count: number
}

describe('MemoryCollection', () => {
  async function expectSelectorRejection (promise: Promise<unknown>): Promise<void> {
    try {
      await promise
      expect.fail('Expected selector to be rejected')
    } catch (error) {
      expect(error).to.be.instanceOf(TypeError)
    }
  }

  it('supports exact-match reads and constrained updates', async () => {
    const collection = new MemoryCollection<TestDocument>()
    const inserted = await collection.insert({ owner: 'alice', count: 1 })

    expect(await collection.findOne({ _id: inserted._id })).to.deep.include({ owner: 'alice', count: 1 })
    expect(await collection.update({ _id: inserted._id }, { $inc: { count: 2 } })).to.deep.include({ modified: 1 })
    expect(await collection.update({ _id: inserted._id }, { $set: { owner: 'bob' } })).to.deep.include({ modified: 1 })
    expect(await collection.find({ owner: 'bob' })).to.have.lengthOf(1)
  })

  it('rejects executable and operator-based selectors', async () => {
    const collection = new MemoryCollection<TestDocument>()
    await collection.insert({ owner: 'alice', count: 1 })

    await expectSelectorRejection(collection.find({ $where: 'sleep(2000)' }))
    await expectSelectorRejection(collection.find({ owner: { $ne: 'alice' } }))
  })

  it('parses the legacy numeric product lookup without evaluating JavaScript', async () => {
    const collection = new MemoryCollection<TestDocument & { product: number }>()
    await collection.insert({ owner: 'alice', count: 1, product: 7 })

    expect(await collection.find({ $where: 'this.product == 7' })).to.have.lengthOf(1)
    await expectSelectorRejection(collection.find({ $where: 'this.product == 7 || sleep(2000)' }))
  })

  it('returns copies instead of mutable storage references', async () => {
    const collection = new MemoryCollection<TestDocument>()
    const inserted = await collection.insert({ owner: 'alice', count: 1 })
    inserted.owner = 'mallory'

    expect(await collection.findOne({ _id: inserted._id })).to.have.property('owner', 'alice')
  })
})
