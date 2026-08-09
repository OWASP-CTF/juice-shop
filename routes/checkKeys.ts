import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import logger from '../lib/logger'
import { challenges } from '../data/datacache'

interface JuicyWallet {
  privateKey: string
  publicKey: string
  address: string
}

/* The wallet used to be derived from a fixed seed phrase that was written down in one of the
   shop's own feedback entries, which handed its private key to anyone who read it. It is now
   generated once at runtime, so the key only ever exists in memory and is never committed,
   printed or otherwise recoverable from the application. */
let juicyWallet: Promise<JuicyWallet> | undefined

const walletOfTheShop = async (): Promise<JuicyWallet> => {
  if (juicyWallet === undefined) {
    juicyWallet = (async () => {
      const { Wallet } = await import('ethers')
      const wallet = Wallet.createRandom()
      return { privateKey: wallet.privateKey, publicKey: wallet.publicKey, address: wallet.address }
    })()
  }
  return await juicyWallet
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await walletOfTheShop()
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return req.body.privateKey === privateKey
      })
      if (req.body.privateKey === privateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (req.body.privateKey === address) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (req.body.privateKey === publicKey) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else {
          res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
        }
      }
    } catch (error) {
      logger.warn(`Could not check the submitted key: ${utils.getErrorMessage(error)}`)
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      logger.warn(`Could not read the unlock status: ${utils.getErrorMessage(error)}`)
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
