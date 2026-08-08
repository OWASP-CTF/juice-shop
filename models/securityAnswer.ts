/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'
import * as security from '../lib/insecurity'

class SecurityAnswer extends Model<
InferAttributes<SecurityAnswer>,
InferCreationAttributes<SecurityAnswer>
> {
  declare SecurityQuestionId: number
  declare UserId: number
  declare id: CreationOptional<number>
  declare answer: string

  toJSON () {
    const values = { ...this.get() }
    delete values.answer
    return values
  }
}

const SecurityAnswerModelInit = (sequelize: Sequelize) => {
  SecurityAnswer.init(
    {
      UserId: {
        type: DataTypes.INTEGER,
        unique: true,
        allowNull: false
      },
      SecurityQuestionId: {
        type: DataTypes.INTEGER,
        allowNull: false
      },

      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      answer: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          notEmpty: true,
          len: [1, 1024]
        },
        set (answer: string) {
          this.setDataValue('answer', security.passwordHash(answer))
        }
      }
    },
    {
      tableName: 'SecurityAnswers',
      defaultScope: {
        attributes: { exclude: ['answer'] }
      },
      scopes: {
        withAnswer: {
          attributes: { include: ['answer'] }
        }
      },
      sequelize
    }
  )
}

export { SecurityAnswer as SecurityAnswerModel, SecurityAnswerModelInit }
