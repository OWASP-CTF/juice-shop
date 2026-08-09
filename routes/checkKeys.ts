import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

interface ShopWallet { privateKey: string, publicKey: string, address: string }

// The wallet was derived from a mnemonic written into this file, so its private key was public
// knowledge to anyone reading the source. It is now created once per boot and only held in memory.
let shopWallet: Promise<ShopWallet> | undefined

const walletOfTheShop = async (): Promise<ShopWallet> => {
  shopWallet ??= import('ethers').then(({ Wallet }) => {
    const { privateKey, publicKey, address } = Wallet.createRandom()
    return { privateKey, publicKey, address }
  })
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
