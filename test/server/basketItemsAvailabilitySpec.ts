/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { BasketItemModel } from '../../models/basketitem'
import { ProductModel } from '../../models/product'
import { addBasketItem } from '../../routes/basketItems'

const expect = chai.expect
chai.use(sinonChai)

describe('basket item availability', () => {
  it('rejects a withdrawn product before adding it to the basket', async () => {
    const findProduct = sinon.stub(ProductModel, 'findOne').resolves(null)
    const buildItem = sinon.stub(BasketItemModel, 'build')
    const req = {
      rawBody: '{"ProductId":42,"BasketId":1,"quantity":1}',
      headers: {}
    } as any
    const res = { status: sinon.stub().returnsThis(), json: sinon.spy() } as any

    try {
      await addBasketItem()(req, res, sinon.spy())

      expect(findProduct).to.have.been.calledWith({ where: { id: 42 } })
      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ error: 'This product is no longer available.' })
      expect(buildItem.called).to.equal(false)
    } finally {
      findProduct.restore()
      buildItem.restore()
    }
  })

  it('continues to add a product that is on sale', async () => {
    const findProduct = sinon.stub(ProductModel, 'findOne').resolves({ id: 42 } as ProductModel)
    const save = sinon.stub().resolves({ ProductId: 42, BasketId: 1, quantity: 1 })
    const buildItem = sinon.stub(BasketItemModel, 'build').returns({ save } as any)
    const req = {
      rawBody: '{"ProductId":42,"BasketId":1,"quantity":1}',
      headers: {}
    } as any
    const res = { json: sinon.spy() } as any

    try {
      await addBasketItem()(req, res, sinon.spy())

      expect(buildItem).to.have.been.calledWith({ ProductId: 42, BasketId: 1, quantity: 1 })
      expect(save.calledOnce).to.equal(true)
      expect(res.json).to.have.been.calledWith({
        status: 'success',
        data: { ProductId: 42, BasketId: 1, quantity: 1 }
      })
    } finally {
      findProduct.restore()
      buildItem.restore()
    }
  })
})
