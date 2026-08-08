/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type Sequelize
} from 'sequelize'

class Captcha extends Model<
InferAttributes<Captcha>,
InferCreationAttributes<Captcha>
> {
  declare captchaId: number
  declare captcha: string
  declare answer: string

  toJSON () {
    const values = { ...this.get() }
    delete values.answer
    return values
  }
}

const CaptchaModelInit = (sequelize: Sequelize) => {
  Captcha.init(
    {
      captchaId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        unique: true
      },
      captcha: {
        type: DataTypes.STRING,
        allowNull: false
      },
      answer: {
        type: DataTypes.STRING,
        allowNull: false
      }
    },
    {
      tableName: 'Captchas',
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

export { Captcha as CaptchaModel, CaptchaModelInit }
