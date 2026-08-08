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
          let sanitizedComment: string
          if (utils.isChallengeEnabled(challenges.persistedXssFeedbackChallenge)) {
            sanitizedComment = security.sanitizeHtml(comment)
            challengeUtils.solveIf(challenges.persistedXssFeedbackChallenge, () => {
              return utils.contains(
                sanitizedComment,
                '<iframe src="javascript:alert(`xss`)">'
              )
            })
          }
          // Always apply secure sanitization to prevent XSS
          sanitizedComment = security.sanitizeSecure(comment)
          this.setDataValue('comment', sanitizedComment)
        }
      },
      rating: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          min: 1,
          max: 5
        },
        set (rating: number) {
          if (Number(rating) === 0) {
            challengeUtils.solveIf(challenges.zeroStarsChallenge, () => { return true })
            // Block zero-star ratings: reject by keeping current/default value
            // The Sequelize min:1 validation will reject this on save
            this.setDataValue('rating', rating)
            return
          }
          this.setDataValue('rating', rating)
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
