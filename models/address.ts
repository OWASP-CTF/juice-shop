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
import * as security from '../lib/insecurity'
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
        type: DataTypes.INTEGER
      },
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      fullName: {
        type: DataTypes.STRING,
        set (fullName: string) {
          this.setDataValue('fullName', security.sanitizeSecure(fullName ?? ''))
        }
      },
      mobileNum: {
        type: DataTypes.INTEGER,
        validate: {
          isInt: true,
          min: 1000000,
          max: 9999999999
        }
      },
      zipCode: {
        type: DataTypes.STRING,
        validate: {
          len: [1, 8]
        }
      },
      streetAddress: {
        type: DataTypes.STRING,
        validate: {
          len: [1, 160]
        },
        set (streetAddress: string) {
          this.setDataValue('streetAddress', security.sanitizeSecure(streetAddress ?? ''))
        }
      },
      city: {
        type: DataTypes.STRING,
        set (city: string) {
          this.setDataValue('city', security.sanitizeSecure(city ?? ''))
        }
      },
      state: {
        type: DataTypes.STRING,
        set (state: string | null) {
          this.setDataValue('state', state == null ? state : security.sanitizeSecure(state))
        }
      },
      country: {
        type: DataTypes.STRING,
        set (country: string) {
          this.setDataValue('country', security.sanitizeSecure(country ?? ''))
        }
      }
    },
    {
      tableName: 'Addresses',
      sequelize
    }
  )
}

export { Address as AddressModel, AddressModelInit }
