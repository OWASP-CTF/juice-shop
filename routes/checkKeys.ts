import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

// The seed phrase that used to be written out here derived the very key this endpoint
// checks for, and the phrase travelled with the source, so the key it protects was known
// to anybody holding a copy. The wallet is generated once per process instead: the check
// and its hints behave exactly as before, the key simply is not written down anywhere.
let walletPromise: Promise<{ privateKey: string, publicKey: string, address: string }> | null = null

async function juicyNftWallet () {
  if (walletPromise === null) {
    walletPromise = import('ethers').then(({ Wallet }) => {
      const wallet = Wallet.createRandom()
      return { privateKey: wallet.privateKey, publicKey: wallet.publicKey, address: wallet.address }
    }).catch((error: unknown) => {
      walletPromise = null
      throw error
    })
  }
  return await walletPromise
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await juicyNftWallet()
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
