/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */

import * as security from '../lib/insecurity'
import {
  Model,
  type InferAttributes,
  type InferCreationAttributes,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'

class Memory extends Model<
InferAttributes<Memory>,
InferCreationAttributes<Memory>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare caption: string
  declare imagePath: string
}

const MemoryModelInit = (sequelize: Sequelize) => {
  Memory.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      caption: {
        type: DataTypes.STRING,
        set (caption: string) {
          // Captions are echoed into the GDPR data export, which the frontend
          // writes into a new window, so they have to be sanitized on the way in
          // like the user and feedback models already are.
          this.setDataValue('caption', security.sanitizeSecure(caption))
        }
      },
      imagePath: DataTypes.STRING
    },
    {
      tableName: 'Memories',
      sequelize
    }
  )
}

export { Memory as MemoryModel, MemoryModelInit }
