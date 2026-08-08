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

class Delivery extends Model<
InferAttributes<Delivery>,
InferCreationAttributes<Delivery>
> {
  declare id: CreationOptional<number>
  declare name: string
  declare price: number
  declare deluxePrice: number
  declare eta: number
  declare icon: string
}

const DeliveryModelInit = (sequelize: Sequelize) => {
  Delivery.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      price: {
        type: DataTypes.FLOAT,
        allowNull: false,
        validate: { min: 0 }
      },
      deluxePrice: {
        type: DataTypes.FLOAT,
        allowNull: false,
        validate: { min: 0 }
      },
      eta: {
        type: DataTypes.FLOAT,
        allowNull: false,
        validate: { min: 0 }
      },
      icon: {
        type: DataTypes.STRING,
        allowNull: false
      }
    },
    {
      tableName: 'Deliveries',
      sequelize
    }
  )
}

export { Delivery as DeliveryModel, DeliveryModelInit }
