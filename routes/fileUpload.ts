/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import unzipper from 'unzipper'
import { type NextFunction, type Request, type Response } from 'express'

import * as utils from '../lib/utils'

function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

async function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if ((file?.buffer) != null) {
      try {
        const destinationDir = path.resolve('uploads/complaints')
        const archive = await unzipper.Open.buffer(file.buffer)
        const totalSize = archive.files.reduce((size, entry) => size + entry.uncompressedSize, 0)
        if (totalSize > 1000000) {
          res.status(413).json({ error: 'Uncompressed archive is too large' })
          return
        }
        for (const entry of archive.files) {
          if (entry.type === 'Directory') continue
          const absolutePath = path.resolve(destinationDir, entry.path)
          const relativePath = path.relative(destinationDir, absolutePath)
          if (relativePath === '' || relativePath === '..' || relativePath.startsWith('..' + path.sep) || path.isAbsolute(relativePath)) {
            res.status(400).json({ error: 'Archive contains an invalid path' })
            return
          }
          await fs.promises.mkdir(path.dirname(absolutePath), { recursive: true })
          await fs.promises.writeFile(absolutePath, await entry.buffer(), { flag: 'wx' })
        }
      } catch (error) {
        res.status(400).json({ error: 'Invalid archive' })
        return
      }
    }
    res.status(204).end()
  } else {
    next()
  }
}

function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null && file.size > 100000) {
    res.status(413).json({ error: 'File is too large' })
    return
  }
  next()
}

function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  if (fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml') {
    next()
  } else {
    res.status(415).json({ error: 'Unsupported file type' })
  }
}

function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    res.status(410).json({ error: 'B2B customer complaints via XML upload have been deprecated for security reasons' })
    return
  }
  next()
}

function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    res.status(410).json({ error: 'B2B customer complaints via YAML upload have been deprecated for security reasons' })
    return
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
