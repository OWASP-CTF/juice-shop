/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import path from 'node:path'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { checkUploadSize, checkFileType, handleXmlUpload, handleYamlUpload, resolveArchiveEntryPath } from '../../routes/fileUpload'

const expect = chai.expect

describe('fileUpload', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    req = { file: { originalname: '' } }
    res = {
      status (status: number) {
        this.statusCode = status
        return this
      },
      end () {}
    }
    save = () => ({
      then () { }
    })
  })

  describe('should not solve "uploadSizeChallenge" when file size is', () => {
    const sizes = [0, 1, 100, 1000, 10000, 99999, 100000]
    sizes.forEach(size => {
      it(`${size} bytes`, () => {
        challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
        req.file.size = size

        checkUploadSize(req, res, () => {})

        expect(challenges.uploadSizeChallenge.solved).to.equal(false)
      })
    })
  })

  it('should solve "uploadSizeChallenge" when file size exceeds 100000 bytes', () => {
    challenges.uploadSizeChallenge = { solved: false, save } as unknown as Challenge
    req.file.size = 100001

    checkUploadSize(req, res, () => {})

    expect(challenges.uploadSizeChallenge.solved).to.equal(true)
  })

  it('should solve "uploadTypeChallenge" when file type is not PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.exe'

    checkFileType(req, res, () => {})

    expect(challenges.uploadTypeChallenge.solved).to.equal(true)
  })

  it('should not solve "uploadTypeChallenge" when file type is PDF', () => {
    challenges.uploadTypeChallenge = { solved: false, save } as unknown as Challenge
    req.file.originalname = 'hack.pdf'

    checkFileType(req, res, () => {})

    expect(challenges.uploadTypeChallenge.solved).to.equal(false)
  })

  describe('archive entry path validation', () => {
    it('keeps ordinary and nested files inside the complaint upload directory', () => {
      expect(resolveArchiveEntryPath('invoice.txt')).to.equal(path.resolve('uploads/complaints/invoice.txt'))
      expect(resolveArchiveEntryPath('customer/invoice.txt')).to.equal(path.resolve('uploads/complaints/customer/invoice.txt'))
    })

    it('rejects paths outside the complaint upload directory', () => {
      expect(resolveArchiveEntryPath('../../ftp/legal.md')).to.equal(undefined)
      expect(resolveArchiveEntryPath('/tmp/legal.md')).to.equal(undefined)
      expect(resolveArchiveEntryPath('')).to.equal(undefined)
      expect(resolveArchiveEntryPath('invoice.txt\0.exe')).to.equal(undefined)
    })
  })

  it('rejects XML without parsing it or solving parser challenges', () => {
    challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
    challenges.xxeFileDisclosureChallenge = { solved: false, save } as unknown as Challenge
    challenges.xxeDosChallenge = { solved: false, save } as unknown as Challenge
    req.file = { originalname: 'payload.xml', buffer: Buffer.from('<!ENTITY xxe SYSTEM "file:///etc/passwd">') }
    const errors: Error[] = []

    handleXmlUpload(req, res, (err?: unknown) => { if (err instanceof Error) errors.push(err) })

    expect(res.statusCode).to.equal(410)
    expect(errors).to.have.lengthOf(1)
    expect(challenges.deprecatedInterfaceChallenge.solved).to.equal(false)
    expect(challenges.xxeFileDisclosureChallenge.solved).to.equal(false)
    expect(challenges.xxeDosChallenge.solved).to.equal(false)
  })

  it('rejects YAML without parsing it or solving parser challenges', () => {
    challenges.deprecatedInterfaceChallenge = { solved: false, save } as unknown as Challenge
    challenges.yamlBombChallenge = { solved: false, save } as unknown as Challenge
    req.file = { originalname: 'payload.yaml', buffer: Buffer.from('bomb: &bomb [*bomb]') }
    const errors: Error[] = []

    handleYamlUpload(req, res, (err?: unknown) => { if (err instanceof Error) errors.push(err) })

    expect(res.statusCode).to.equal(410)
    expect(errors).to.have.lengthOf(1)
    expect(challenges.deprecatedInterfaceChallenge.solved).to.equal(false)
    expect(challenges.yamlBombChallenge.solved).to.equal(false)
  })
})
