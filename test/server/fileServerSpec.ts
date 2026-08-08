/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { servePublicFiles } from '../../routes/fileServer'
const expect = chai.expect
chai.use(sinonChai)

describe('fileServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), json: sinon.spy() }
    res.status = sinon.stub().returns(res)
    req = { params: {}, query: {} }
    next = sinon.spy()
  })

  it('serves the public legal document', () => {
    req.params.file = 'legal.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md/))
  })

  it('serves generated order PDFs with expected names', () => {
    req.params.file = 'order_abcd-0123456789abcdef.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]order_abcd-0123456789abcdef\.pdf/))
  })

  for (const file of [
    'test.pdf',
    'test.md',
    'incident-support.kdbx',
    'acquisitions.md',
    '../../../../nice.try',
    'eastere.gg%00.md',
    'package.json.bak%00.md',
    'coupons_2013.md.bak%00.md',
    'suspicious_errors.yml%00.md'
  ]) {
    it(`rejects non-public file ${file}`, () => {
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.status).to.have.been.calledWith(403)
      expect(res.sendFile.called).to.equal(false)
    })
  }
})
