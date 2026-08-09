import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

interface ServerWallet {
  privateKey: string
  publicKey: string
  address: string
}

let serverWallet: Promise<ServerWallet> | undefined

async function getServerWallet (): Promise<ServerWallet> {
  serverWallet ??= import('ethers').then(({ Wallet }) => {
    const wallet = Wallet.createRandom()
    return {
      privateKey: wallet.privateKey,
      publicKey: wallet.signingKey.publicKey,
      address: wallet.address
    }
  })
  return await serverWallet
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const wallet = await getServerWallet()
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => req.body.privateKey === wallet.privateKey)
      if (req.body.privateKey === wallet.privateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else if (req.body.privateKey === wallet.address) {
        res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
      } else if (req.body.privateKey === wallet.publicKey) {
        res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
      } else {
        res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
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