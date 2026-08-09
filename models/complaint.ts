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

class Complaint extends Model<
InferAttributes<Complaint>,
InferCreationAttributes<Complaint>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare message: string
  declare file: CreationOptional<string>
}

const ComplaintModelInit = (sequelize: Sequelize) => {
  Complaint.init(
    {
      UserId: {
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      message: {
        type: DataTypes.STRING,
        set (message: string) {
          this.setDataValue('message', security.stripExternalReferences(message))
        }
      },
      file: DataTypes.STRING
    },
    {
      tableName: 'Complaints',
      sequelize
    }
  )
}

export { Complaint as ComplaintModel, ComplaintModelInit }
