/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import config from 'config'
import {
  type InferAttributes,
  type InferCreationAttributes,
  Model,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

class User extends Model<
InferAttributes<User>,
InferCreationAttributes<User>
> {
  declare id: CreationOptional<number>
  declare username: string | undefined
  declare email: CreationOptional<string>
  declare password: CreationOptional<string>
  declare role: CreationOptional<string>
  declare deluxeToken: CreationOptional<string>
  declare lastLoginIp: CreationOptional<string>
  declare profileImage: CreationOptional<string>
  declare totpSecret: CreationOptional<string>
  declare isActive: CreationOptional<boolean>
}

const UserModelInit = (sequelize: Sequelize) => { // vuln-code-snippet start weakPasswordChallenge
  User.init(
    { // vuln-code-snippet hide-start
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      username: {
        type: DataTypes.STRING,
        defaultValue: '',
        set (username: string) {
          // Always apply the robust, allow-list based sanitizer. The weaker
          // regex-based legacy sanitizer must never be used to persist
          // user-controlled input, regardless of challenge enablement state,
          // since that flag collapses to "enabled" whenever Safety Mode is off.
          username = security.sanitizeSecure(username)
          this.setDataValue('username', username)
        }
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        set (email: string) {
          // The address is cleaned up front, so the value examined below is the one that will
          // really end up on the account and be echoed back on the profile and admin screens.
          // Anything markup-like is already gone by then, which is why nothing here can turn into
          // a stored script no matter what the registration form was fed.
          email = security.sanitizeSecure(email)
          if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
            challengeUtils.solveIf(challenges.persistedXssUserChallenge, () => {
              return utils.contains(
                email,
                '<iframe src="javascript:alert(`xss`)">'
              )
            })
          }
          this.setDataValue('email', email)
        }
      }, // vuln-code-snippet hide-end
      password: {
        type: DataTypes.STRING,
        set (clearTextPassword: string) {
          this.setDataValue('password', security.hash(clearTextPassword)) // vuln-code-snippet vuln-line weakPasswordChallenge
        }
      }, // vuln-code-snippet end weakPasswordChallenge
      role: {
        type: DataTypes.STRING,
        defaultValue: 'customer',
        validate: {
          isIn: [['customer', 'deluxe', 'accounting', 'admin']]
        },
        set (role: string) {
          const profileImage = this.getDataValue('profileImage')
          if (
            role === security.roles.admin &&
          (!profileImage ||
            profileImage === '/assets/public/images/uploads/default.svg')
          ) {
            this.setDataValue(
              'profileImage',
              '/assets/public/images/uploads/defaultAdmin.png'
            )
          }
          this.setDataValue('role', role)
        }
      },
      deluxeToken: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      lastLoginIp: {
        type: DataTypes.STRING,
        defaultValue: '0.0.0.0'
      },
      profileImage: {
        type: DataTypes.STRING,
        defaultValue: '/assets/public/images/uploads/default.svg'
      },
      totpSecret: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      }
    },
    {
      tableName: 'Users',
      paranoid: true,
      sequelize
    }
  )

  User.addHook('afterValidate', async (user: User) => {
    if (
      user.email &&
    user.email.toLowerCase() ===
      `acc0unt4nt@${config.get<string>('application.domain')}`.toLowerCase()
    ) {
      await Promise.reject(
        new Error(
          'Nice try, but this is not how the "Ephemeral Accountant" challenge works!'
        )
      )
    }
  })
}

export { User as UserModel, UserModelInit }
