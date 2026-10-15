/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as models from '../models/index'
import * as utils from '../lib/utils'

const MAX_EMAIL_LENGTH = 254
const MAX_PASSWORD_LENGTH = 128

const EMAIL_PATTERN =
  /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/

/**
 * Validate that a credential is a non-empty string within the allowed
 * length. This also rejects arrays and objects supplied in request bodies.
 */
function isValidCredential (
  value: unknown,
  maxLength: number
): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLength
  )
}

/**
 * Validate the email format and length.
 *
 * Email validation is an input-quality check, not a substitute for
 * parameterised database queries.
 */
function isValidEmail (value: unknown): value is string {
  return (
    isValidCredential(value, MAX_EMAIL_LENGTH) &&
    EMAIL_PATTERN.test(value)
  )
}

/**
 * Return a generic authentication failure.
 */
function rejectLogin (res: Response): void {
  res.status(401).send(res.__('Invalid email or password.'))
}

/**
 * Login controller.
 */
export function login () {
  /**
   * Complete login after credentials have been verified.
   */
  function afterLogin (
    user: UserModel,
    res: Response,
    next: NextFunction
  ): void {
    try {
      verifyPostLoginChallenges(user)

      BasketModel.findOrCreate({
        where: {
          UserId: user.id
        }
      })
        .then(([basket]: [BasketModel, boolean]) => {
          const authenticatedUser = {
            data: user,
            bid: basket.id
          }

          const token = security.authorize(authenticatedUser)

          security.authenticatedUsers.put(
            token,
            authenticatedUser
          )

          res.json({
            authentication: {
              token,
              bid: basket.id,
              umail: user.email
            }
          })
        })
        .catch((error: Error) => {
          next(error)
        })
    } catch (error) {
      next(error)
    }
  }

  /**
   * Process login requests.
   */
  return (
    req: Request,
    res: Response,
    next: NextFunction
  ): void => {
    const body: unknown = req.body

    if (
      body === null ||
      typeof body !== 'object' ||
      Array.isArray(body)
    ) {
      rejectLogin(res)
      return
    }

    const { email, password } = body as {
      email?: unknown
      password?: unknown
    }

    // Validate input before performing database operations.
    if (
      !isValidEmail(email) ||
      !isValidCredential(password, MAX_PASSWORD_LENGTH)
    ) {
      rejectLogin(res)
      return
    }

    // Preserve existing Juice Shop challenge behaviour.
    verifyPreLoginChallenges(req)

    /*
     * Use bound parameters so input is treated as data rather than
     * concatenated into SQL syntax.
     *
     * This query retains the existing password-hashing behaviour.
     * Password-hash migration should be handled separately.
     */
    models.sequelize.query(
      `SELECT *
       FROM Users
       WHERE email = $email
         AND password = $password
         AND deletedAt IS NULL`,
      {
        bind: {
          email,
          password: security.hash(password)
        },
        model: UserModel,
        plain: true
      }
    )
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)

        if (!user.data?.id) {
          rejectLogin(res)
          return
        }

        /*
         * Require the application's second-factor workflow when
         * a TOTP secret is configured.
         */
        if (
          user.data.totpSecret !== undefined &&
          user.data.totpSecret !== null &&
          user.data.totpSecret !== ''
        ) {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })

          return
        }

        afterLogin(user.data, res, next)
      })
      .catch((error: Error) => {
        // Pass the error to the central Express error handler.
        // Do not expose database internals in the response.
        next(error)
      })
  }

  /**
   * Check existing pre-login Juice Shop challenges.
   */
  function verifyPreLoginChallenges (req: Request): void {
    challengeUtils.solveIf(
      challenges.weakPasswordChallenge,
      () => {
        return (
          req.body.email ===
            'admin@' + config.get<string>('application.domain') &&
          req.body.password === 'admin123'
        )
      }
    )

    challengeUtils.solveIf(
      challenges.loginSupportChallenge,
      () => {
        return (
          req.body.email ===
            'support@' + config.get<string>('application.domain') &&
          req.body.password ===
            'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
        )
      }
    )

    challengeUtils.solveIf(
      challenges.loginRapperChallenge,
      () => {
        return (
          req.body.email ===
            'mc.safesearch@' + config.get<string>('application.domain') &&
          req.body.password === 'Mr. N00dles'
        )
      }
    )

    challengeUtils.solveIf(
      challenges.loginAmyChallenge,
      () => {
        return (
          req.body.email ===
            'amy@' + config.get<string>('application.domain') &&
          req.body.password === 'K1f.....................'
        )
      }
    )

    challengeUtils.solveIf(
      challenges.dlpPasswordSprayingChallenge,
      () => {
        return (
          req.body.email ===
            'J12934@' + config.get<string>('application.domain') &&
          req.body.password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
        )
      }
    )

    challengeUtils.solveIf(
      challenges.oauthUserPasswordChallenge,
      () => {
        return (
          req.body.email === 'bjoern.kimminich@gmail.com' &&
          req.body.password ===
            'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
        )
      }
    )

    challengeUtils.solveIf(
      challenges.exposedCredentialsChallenge,
      () => {
        return (
          req.body.email ===
            'testing@' + config.get<string>('application.domain') &&
          req.body.password === 'IamUsedForTesting'
        )
      }
    )
  }

  /**
   * Check existing post-login Juice Shop challenges.
   */
  function verifyPostLoginChallenges (user: UserModel): void {
    challengeUtils.solveIf(
      challenges.loginAdminChallenge,
      () => user.id === users.admin.id
    )

    challengeUtils.solveIf(
      challenges.loginJimChallenge,
      () => user.id === users.jim.id
    )

    challengeUtils.solveIf(
      challenges.loginBenderChallenge,
      () => user.id === users.bender.id
    )

    challengeUtils.solveIf(
      challenges.ghostLoginChallenge,
      () => user.id === users.chris.id
    )

    if (
      challengeUtils.notSolved(
        challenges.ephemeralAccountantChallenge
      ) &&
      user.email ===
        'acc0unt4nt@' + config.get<string>('application.domain') &&
      user.role === 'accounting'
    ) {
      UserModel.count({
        where: {
          email:
            'acc0unt4nt@' + config.get<string>('application.domain')
        }
      })
        .then((count) => {
          if (count === 0) {
            challengeUtils.solve(
              challenges.ephemeralAccountantChallenge
            )
          }
        })
        .catch(() => {
          throw new Error(
            'Unable to verify challenges! Try again'
          )
        })
    }
  }
}