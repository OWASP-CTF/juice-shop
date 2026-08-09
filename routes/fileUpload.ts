/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import vm from 'node:vm'
import path from 'node:path'
import yaml from 'js-yaml'
import libxml from 'libxmljs2'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

// A YAML document referencing this many anchors is an expansion bomb, not a
// legitimate complaint. Generous enough that ordinary anchor reuse is unaffected.
const MAX_YAML_ALIASES = 50

// Counting alias tokens does not bound the blow-up on its own: expansion is width ^ depth,
// so 8 tiers of 6 references is only 48 tokens and still expands to 1.7 million nodes. Bound
// the expansion itself as well - the resolved document may not inflate past this many bytes.
const MAX_YAML_EXPANSION_BYTES = 8 * 1024 * 1024

function hasExcessiveAliases (data: string) {
  const aliases = data.match(new RegExp('[*][0-9a-zA-Z_-]+', 'g'))
  return aliases !== null && aliases.length > MAX_YAML_ALIASES
}

// Every reference to an anchor duplicates whatever that anchor holds, and anchors that
// reference other anchors multiply, so the product of the per-anchor reference counts is an
// upper bound on how often the innermost node gets materialised. Multiplied by the document
// size that is a conservative estimate of the expanded document. Counting each name over the
// whole document keeps the estimate independent of layout, so spreading a sequence across
// several lines or padding it with decoy anchors cannot talk the estimate down.
function expandsBeyondBudget (data: string) {
  const aliases = data.match(new RegExp('[*][0-9a-zA-Z_-]+', 'g'))
  if (aliases === null) {
    return false
  }
  const references = new Map<string, number>()
  for (const alias of aliases) {
    const name = alias.slice(1)
    references.set(name, (references.get(name) ?? 0) + 1)
  }
  const budget = Math.max(1, Math.floor(MAX_YAML_EXPANSION_BYTES / Math.max(1, data.length)))
  let factor = 1
  for (const count of references.values()) {
    factor *= count
    if (factor > budget) {
      return true
    }
  }
  return false
}

// An archive entry name is attacker controlled and is never allowed to address anything
// but a plain relative name below the extraction root. Rooted names, names carrying a ..
// segment, names using backslashes as separators and names smuggling a NUL are refused
// before they are ever resolved. This runs in addition to - not instead of - the
// containment check on the resolved path, so a name that slips past one still meets the
// other.
function isUnsafeEntryName (fileName: unknown): boolean {
  if (typeof fileName !== 'string' || fileName === '' || fileName.includes('\0')) {
    return true
  }
  const normalized = fileName.split('\\').join('/')
  if (path.posix.isAbsolute(normalized) || path.win32.isAbsolute(normalized)) {
    return true
  }
  return normalized.split('/').includes('..')
}

// String containment only proves the *lexical* path stays below the upload directory. A
// symlink somewhere along the way would still let the write land outside it, so resolve
// the parent directory for real and require that the physical location is below the
// physical upload directory as well. A parent that does not exist resolves to nothing and
// is refused rather than written.
function parentResolvesInsideUploadRoot (absolutePath: string, uploadRoot: string) {
  try {
    const realRoot = fs.realpathSync(uploadRoot)
    const realParent = fs.realpathSync(path.dirname(absolutePath))
    return realParent === realRoot || realParent.startsWith(realRoot + path.sep)
  } catch {
    return false
  }
}

// Opening with O_NOFOLLOW closes the remaining gap: if the final path component is itself
// a symlink the open fails instead of quietly writing through it to the link's target.
function openContainedFileForWriting (absolutePath: string): number | null {
  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0
  try {
    return fs.openSync(absolutePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | noFollow)
  } catch {
    return null
  }
}

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
      // The uploaded file's own name is attacker controlled and is only ever used to stage
      // the archive somewhere scratch before it is read back, so keep nothing but the base
      // name. Joining the raw name let ../ walk out of the temp directory and drop the raw
      // upload bytes at any path of the attacker's choosing. A private temp directory also
      // removes the collision between two uploads sharing a name.
      const filename = path.basename(file.originalname.toLowerCase())
      const tempFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'juice-shop-upload-')), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err); return }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                const uploadRoot = path.resolve('uploads/complaints')
                const absolutePath = isUnsafeEntryName(fileName) ? null : path.resolve(uploadRoot, String(fileName))
                // The resolved destination must sit beneath the upload directory, so an
                // entry name containing ../ cannot escape it. The name check and the
                // real-path check are layered on top of that string check, not in place of
                // it: the name must be an ordinary relative name, the resolved path must be
                // lexically below the upload directory, and the directory it lands in must
                // physically be the upload directory once symlinks are resolved.
                if (absolutePath !== null && absolutePath.startsWith(uploadRoot + path.sep) && parentResolvesInsideUploadRoot(absolutePath, uploadRoot)) {
                  // Only a destination we really write to counts. Asking for a path
                  // outside the upload directory no longer writes anything, so it is not
                  // an overwrite either.
                  challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                  const outFd = openContainedFileForWriting(absolutePath)
                  if (outFd === null) {
                    // The destination could not be opened without following a link out of
                    // the upload directory, so nothing is written for this entry.
                    entry.autodrain()
                    return
                  }
                  entry.pipe(fs.createWriteStream(absolutePath, { fd: outFd }).on('error', function (err) { next(err) }))
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
        // noent: false leaves external entities unresolved; nonet: true refuses network fetches.
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
      if (hasExcessiveAliases(data) || expandsBeyondBudget(data)) {
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: too many aliases (' + file.originalname + ')'))
        return
      }
      try {
        const sandbox = { yaml, data }
        vm.createContext(sandbox)
        const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
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
