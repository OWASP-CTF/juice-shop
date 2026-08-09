import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

interface ShopWallet {
  privateKey: string
  publicKey: string
  address: string
}

/* The wallet was derived from a fixed seed phrase written into the shop's own seeded
   feedback, so its private key was readable by anyone who looked. It is generated once at
   runtime instead: the key exists only in this process and is not committed anywhere. */
let shopWallet: Promise<ShopWallet> | undefined

const walletOfTheShop = async (): Promise<ShopWallet> => {
  if (shopWallet === undefined) {
    shopWallet = (async () => {
      const { Wallet } = await import('ethers')
      const wallet = Wallet.createRandom()
      return { privateKey: wallet.privateKey, publicKey: wallet.publicKey, address: wallet.address }
    })()
  }
  return await shopWallet
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
