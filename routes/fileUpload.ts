/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const complaintUploadDirectory = path.resolve('uploads/complaints')

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
      const archive = unzipper.Parse()
        .on('entry', function (entry: any) {
          const absolutePath = resolveArchiveEntryPath(entry.path)
          if (entry.type !== 'File' || absolutePath == null) {
            entry.autodrain()
            return
          }

          fs.mkdir(path.dirname(absolutePath), { recursive: true }, function (err) {
            if (err != null) {
              entry.autodrain()
              next(err)
              return
            }
            entry.pipe(fs.createWriteStream(absolutePath).on('error', function (err) { next(err) }))
          })
        })
        .on('error', function (err: unknown) { next(err) })
      archive.end(file.buffer)
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
    res.status(410)
    next(new Error('B2B customer complaints via XML upload have been deprecated for security reasons.'))
    return
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    res.status(410)
    next(new Error('B2B customer complaints via YAML upload have been deprecated for security reasons.'))
    return
  }
  res.status(204).end()
}

function resolveArchiveEntryPath (fileName: string) {
  if (fileName.includes('\0')) {
    return undefined
  }

  const absolutePath = path.resolve(complaintUploadDirectory, fileName)
  const relativePath = path.relative(complaintUploadDirectory, absolutePath)
  if (relativePath === '' || relativePath === '..' || relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath)) {
    return undefined
  }

  return absolutePath
}

export {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload,
  handleYamlUpload,
  resolveArchiveEntryPath
}
