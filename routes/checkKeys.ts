import crypto from 'node:crypto'
import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

const PRIVATE_KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/
const configuredPrivateKey = process.env.JUICE_SHOP_NFT_PRIVATE_KEY
const privateKey = configuredPrivateKey != null && PRIVATE_KEY_PATTERN.test(configuredPrivateKey)
  ? configuredPrivateKey.toLowerCase()
  : `0x${crypto.randomBytes(32).toString('hex')}`

function matchesPrivateKey (submittedKey: unknown) {
  if (typeof submittedKey !== 'string' || !PRIVATE_KEY_PATTERN.test(submittedKey)) {
    return false
  }
  return crypto.timingSafeEqual(
    Buffer.from(submittedKey.slice(2), 'hex'),
    Buffer.from(privateKey.slice(2), 'hex')
  )
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { Wallet } = await import('ethers')
      const wallet = new Wallet(privateKey)
      const publicKey = wallet.signingKey.publicKey
      const address = wallet.address
      const submittedKey = req.body?.privateKey
      const validPrivateKey = matchesPrivateKey(submittedKey)
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return validPrivateKey
      })
      if (validPrivateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (submittedKey === address) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (submittedKey === publicKey) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else {
          res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
        }
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
