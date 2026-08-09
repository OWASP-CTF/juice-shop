import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

// The wallet is identified by its address and public key throughout the shop, so those stay as
// they are published. Only the private key is a secret, and a seed phrase in the source hands it
// to every reader of the source, so it is minted once per boot and never leaves memory.
const address = '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05'
const publicKey = '0x02c7a2a93289c9fbda5990bac6596993e9bb0a8d3f178175a80b7cfd983983f506'

let shopPrivateKey: Promise<string> | undefined

const privateKeyOfTheShop = async (): Promise<string> => {
  shopPrivateKey ??= import('ethers').then(({ Wallet }) => Wallet.createRandom().privateKey)
  return await shopPrivateKey
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const privateKey = await privateKeyOfTheShop()
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
