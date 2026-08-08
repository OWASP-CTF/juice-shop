/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'

class ImageCaptcha extends Model<
InferAttributes<ImageCaptcha>,
InferCreationAttributes<ImageCaptcha>
> {
  declare id: CreationOptional<number>
  declare image: string
  declare answer: string
  declare UserId: number
  declare createdAt: CreationOptional<Date>

  toJSON () {
    const values = { ...this.get() }
    delete values.answer
    return values
  }
}

const ImageCaptchaModelInit = (sequelize: Sequelize) => {
  ImageCaptcha.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      image: {
        type: DataTypes.STRING,
        allowNull: false
      },
      answer: {
        type: DataTypes.STRING,
        allowNull: false
      },
      UserId: { type: DataTypes.INTEGER, allowNull: false },
      createdAt: DataTypes.DATE
    },
    {
      tableName: 'ImageCaptchas',
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

export { ImageCaptcha as ImageCaptchaModel, ImageCaptchaModelInit }
