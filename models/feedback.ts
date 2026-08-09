/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

class Feedback extends Model<
InferAttributes<Feedback>,
InferCreationAttributes<Feedback>
> {
  declare UserId: number | null
  declare id: CreationOptional<number>
  declare comment: string
  declare rating: number
}
const FeedbackModelInit = (sequelize: Sequelize) => {
  Feedback.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      comment: {
        type: DataTypes.STRING,
        set (comment: string) {
          const sanitizedComment = security.sanitizeHtml(comment)
          if (utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge)) {
            challengeUtils.solveIf(challenges.persistedXssFeedbackChallenge, () => {
              return utils.contains(
                sanitizedComment,
                '<iframe src="javascript:alert(`xss`)">'
              )
            })
          }
          /* Always reach a sanitization fixed point before storing, regardless
             of challenge enablement or application safety mode. */
          this.setDataValue('comment', security.sanitizeSecure(sanitizedComment))
        }
      },
      rating: {
        type: DataTypes.INTEGER,
        allowNull: false,
        /* Only the Angular form enforced the one-to-five star range, so posting
           straight to the API accepted a zero (or otherwise out-of-range)
           rating. The bound is now enforced server-side. */
        validate: {
          min: 1,
          max: 5
        },
        set (rating: number) {
          this.setDataValue('rating', rating)
          challengeUtils.solveIf(challenges.zeroStarsChallenge, () => {
            return Number(rating) === 0
          })
        }
      }
    },
    {
      tableName: 'Feedbacks',
      sequelize
    }
  )
}

export { Feedback as FeedbackModel, FeedbackModelInit }
