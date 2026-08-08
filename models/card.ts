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
class Card extends Model<
InferAttributes<Card>,
InferCreationAttributes<Card>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare fullName: string
  declare cardNum: number
  declare expMonth: number
  declare expYear: number

  toJSON () {
    const values = { ...this.get() }
    delete values.cardNum
    return values
  }
}

const CardModelInit = (sequelize: Sequelize) => {
  Card.init(
    {
      UserId: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      fullName: {
        type: DataTypes.STRING,
        allowNull: false
      },
      cardNum: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          isInt: true,
          min: 1000000000000000,
          max: 9999999999999998
        }
      },
      expMonth: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          isInt: true,
          min: 1,
          max: 12
        }
      },
      expYear: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          isInt: true,
          min: 2080,
          max: 2099
        }
      }
    },
    {
      tableName: 'Cards',
      defaultScope: {
        attributes: { exclude: ['cardNum'] }
      },
      scopes: {
        withCardNumber: {
          attributes: { include: ['cardNum'] }
        }
      },
      sequelize
    }
  )
}

export { Card as CardModel, CardModelInit }
