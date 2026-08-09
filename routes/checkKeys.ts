import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

interface ShopWallet { privateKey: string, publicKey: string, address: string }

// A seed phrase in the source hands its private key to every reader of the source, so the shop
// wallet is minted once per boot and never leaves memory.
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
      const { privateKey } = await walletOfTheShop()
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return req.body.privateKey === privateKey
      })
      if (req.body.privateKey === privateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        // Telling a caller which part of the wallet they guessed narrows the search for the rest.
        res.status(401).json({ success: false, message: 'That is not the private key of my ethereum wallet.', status: challenges.nftUnlockChallenge })
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
