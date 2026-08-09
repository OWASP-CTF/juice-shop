/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import crypto from 'node:crypto'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      /* The archive has to be parked on disk before it can be streamed back out again, and the
         name it is parked under used to be the name the client put in the multipart part. That
         name is a free-form string: nothing in the upload stack strips path separators from it,
         so a part announced as ../../var/www/html/shell.zip resolved out of the temporary folder
         and the request then chose both where a file landed and what went into it - which is the
         whole of an arbitrary file write, before the archive is even opened. Nothing downstream
         needs the submitted name (the extraction step reads the names out of the archive itself),
         so it is not used for the path at all: the staging copy gets a fresh random name that no
         request can steer, and it is removed again once the archive has been read. */
      const tempFile = path.join(os.tmpdir(), `juice-shop-upload-${crypto.randomUUID()}.zip`)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            const archive = fs.createReadStream(tempFile)
            archive.on('close', function () { fs.unlink(tempFile, function () { /* the staged copy is scratch space; failing to reap it must not fail the request */ }) })
            archive
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                // The name inside the archive is attacker-authored and is stripped of every
                // leading step out of the extraction folder before it is joined to it. Doing this
                // first means the destination examined below is the destination that will really
                // be written, so an entry called ../../ftp/legal.md lands in the complaints folder
                // under a harmless name instead of reporting an escape that never happens.
                const declaredName: string = entry.path
                const containedName = path.normalize(declaredName).replace(/^(?:\.\.(?:[/\\]|$))+/, '')
                const uploadsDir = path.resolve('uploads/complaints')
                const absolutePath = path.resolve(uploadsDir, containedName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                if (absolutePath === uploadsDir || absolutePath.startsWith(uploadsDir + path.sep)) {
                  entry.pipe(fs.createWriteStream(absolutePath).on('error', function (err) { next(err) }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      try {
        const sandbox = { libxml, data }
        vm.createContext(sandbox)
        // noent (entity substitution) must stay disabled and nonet (network access) must stay
        // enforced, otherwise a crafted <!ENTITY ... SYSTEM "file:///..."> or "http://..."> in the
        // uploaded XML lets an attacker read local files, trigger SSRF (XXE / CWE-611) or mount an
        // entity-expansion DoS (Challenge-91 / Challenge-92)
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: false, nocdata: true, nonet: true })', sandbox, { timeout: 2000 })
        const xmlString = xmlDoc.toString(false)
        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (utils.contains(errorMessage, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      try {
        // An anchor that is referenced over and over lets a few lines of YAML expand into
        // gigabytes once the parser resolves them, so a document that uses the feature at all is
        // turned away before any parsing starts rather than being raced against a timeout.
        if (/(^|[\s[{,])[*&][^\s*&]/.test(data)) {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: anchors and aliases are not accepted (' + file.originalname + ')'))
          return
        }
        // The default loader understands type tags that construct arbitrary JavaScript; the safe
        // schema is limited to plain data, which is all a complaint document ever needs to be.
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        const yamlString = vm.runInContext('JSON.stringify(yaml.safeLoad(data))', sandbox, { timeout: 2000 })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (utils.contains(errorMessage, 'Invalid string length') || utils.contains(errorMessage, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload
}
