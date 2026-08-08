/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  type CreationOptional,
  type InferAttributes,
  type InferCreationAttributes,
  Model,
  DataTypes,
  type Sequelize
} from 'sequelize'
/* jslint node: true */
class Address extends Model<
InferAttributes<Address>,
InferCreationAttributes<Address>
> {
  declare UserId: number
  declare id: CreationOptional<number>
  declare fullName: string
  declare mobileNum: number
  declare zipCode: string
  declare streetAddress: string
  declare city: string
  declare state: string | null
  declare country: string
}

const AddressModelInit = (sequelize: Sequelize) => {
  Address.init(
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
      mobileNum: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          isInt: true,
          min: 1000000,
          max: 9999999999
        }
      },
      zipCode: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: [1, 8]
        }
      },
      streetAddress: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: [1, 160]
        }
      },
      city: { type: DataTypes.STRING, allowNull: false },
      state: DataTypes.STRING,
      country: { type: DataTypes.STRING, allowNull: false }
    },
    {
      tableName: 'Addresses',
      sequelize
    }
  )
}

export { Address as AddressModel, AddressModelInit }
