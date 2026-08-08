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

class Recycle extends Model<
InferAttributes<Recycle>,
InferCreationAttributes<Recycle>
> {
  declare id: CreationOptional<number>
  declare UserId: number
  declare AddressId: number
  declare quantity: number
  declare isPickup: boolean
  declare date: string
}

const RecycleModelInit = (sequelize: Sequelize) => {
  Recycle.init(
    {
      UserId: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      AddressId: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      quantity: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          isInt: true,
          min: 1
        }
      },
      isPickup: { type: DataTypes.BOOLEAN, defaultValue: false },
      date: DataTypes.DATE
    },
    {
      tableName: 'Recycles',
      sequelize
    }
  )
}

export { Recycle as RecycleModel, RecycleModelInit }
