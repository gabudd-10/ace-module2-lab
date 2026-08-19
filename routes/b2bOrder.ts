/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      let orderLinesData = typeof body.orderLinesData === 'string' ? body.orderLinesData : ''

      const lower = orderLinesData.toLowerCase()
      const blockedChars = ['[', ']', '"', "'", '`', '\\']
      const blockedWords = [
        'this', 'constructor', 'prototype', '__proto__', 'process', 'require',
        'import', 'global', 'function', 'object', 'array', 'string', 'buffer',
        'reflect', 'proxy', 'window', 'self', 'exec', 'spawn', 'child_process',
        'mainmodule', 'eval', '__parent__', '__definegetter__', '__definesetter__',
        '__lookupgetter__', '__lookupsetter__', 'regexp', 'map', 'set', 'promise',
        'error', 'symbol', 'json', 'arguments'
      ]

      const isSuspicious = blockedChars.some(char => lower.includes(char)) ||
                            blockedWords.some(word => lower.includes(word))

      if (isSuspicious) {
        throw new Error('Sanitization check failed: suspicious input detected.')
      }

      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
