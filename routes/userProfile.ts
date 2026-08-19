/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

function safeEval (code: string): string | null {
  if (!code) return null
  code = code.trim()

  const first = code[0]
  const last = code[code.length - 1]
  if ((first === "'" || first === '"' || first === '`') && last === first) {
    const content = code.slice(1, -1)
    if (first === '`' && content.includes('${')) {
      return null
    }
    // Check for unescaped quote of same type
    let escaped = false
    for (let i = 0; i < content.length; i++) {
      const char = content[i]
      if (char === '\\') {
        escaped = !escaped
      } else {
        if (char === first && !escaped) {
          return null
        }
        escaped = false
      }
    }
    // Safe to decode escape sequences
    let result = ''
    let i = 0
    while (i < content.length) {
      const char = content[i]
      if (char === '\\') {
        const nextChar = content[i + 1]
        if (!nextChar) {
          result += '\\'
          i++
          continue
        }
        if (nextChar === '0') {
          result += '\0'
          i += 2
        } else if (nextChar === 'n') {
          result += '\n'
          i += 2
        } else if (nextChar === 'r') {
          result += '\r'
          i += 2
        } else if (nextChar === 't') {
          result += '\t'
          i += 2
        } else if (nextChar === 'b') {
          result += '\b'
          i += 2
        } else if (nextChar === 'f') {
          result += '\f'
          i += 2
        } else if (nextChar === 'u') {
          const hex = content.slice(i + 2, i + 6)
          if (/^[0-9a-fA-F]{4}$/.test(hex)) {
            result += String.fromCharCode(parseInt(hex, 16))
            i += 6
          } else {
            result += '\\u'
            i += 2
          }
        } else if (nextChar === 'x') {
          const hex = content.slice(i + 2, i + 4)
          if (/^[0-9a-fA-F]{2}$/.test(hex)) {
            result += String.fromCharCode(parseInt(hex, 16))
            i += 4
          } else {
            result += '\\x'
            i += 2
          }
        } else {
          result += nextChar
          i += 2
        }
      } else {
        result += char
        i++
      }
    }
    return result
  }

  // Numbers
  if (/^-?\d+(\.\d+)?$/.test(code)) {
    return code
  }

  // Booleans
  if (code === 'true' || code === 'false') {
    return code
  }

  // Null
  if (code === 'null') {
    return 'null'
  }

  return null
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        const evaluated = safeEval(code)
        if (evaluated === null) {
          throw new Error('Invalid username pattern or execution blocked')
        }
        username = evaluated
      } catch (err) {
        username = '\\\\' + username
      }
    } else {
      username = '\\\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
