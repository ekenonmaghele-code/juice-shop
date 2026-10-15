/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const LOG_DIR = path.resolve('logs')

// Allowlist: only letters, digits, dot, underscore and hyphen.
// Slashes, backslashes, null bytes, spaces and encoded separators can never match.
const SAFE_FILE_NAME = /^[A-Za-z0-9._-]+$/

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // 1. Validate the name: string, bounded length, allowlisted characters,
    //    and no leading dot (blocks "..", ".", and hidden files)
    if (
      typeof file !== 'string' ||
      file.length === 0 ||
      file.length > 255 ||
      !SAFE_FILE_NAME.test(file) ||
      file.startsWith('.')
    ) {
      res.status(403)
      next(new Error('Invalid file name!'))
      return
    }

    // 2. Resolve and confirm the result sits directly inside the log directory
    const fullPath = path.resolve(LOG_DIR, file)
    if (path.dirname(fullPath) !== LOG_DIR) {
      res.status(403)
      next(new Error('Invalid file name!'))
      return
    }

    // 3. Serve it, refusing dotfiles and passing any error (e.g. not found) on
    res.sendFile(fullPath, { dotfiles: 'deny' }, (error) => {
      if (error) next(error)
    })
  }
}