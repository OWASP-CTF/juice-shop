import { type Request, type Response } from 'express'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      // The wallet seed phrase is never embedded in the source or shipped to
      // clients: it is supplied through the environment only. Responses are
      // also uniform so they cannot be used as an oracle that tells an attacker
      // how close a guessed key is.
      const { HDNodeWallet } = await import('ethers')
      const mnemonic = process.env.NFT_WALLET_MNEMONIC ?? ''
      if (mnemonic === '') {
        res.status(503).json({ success: false, message: 'Wallet verification is not configured.' })
        return
      }
      const mnemonicWallet = HDNodeWallet.fromPhrase(mnemonic)
      const privateKey = mnemonicWallet.privateKey
      if (typeof req.body.privateKey === 'string' && req.body.privateKey === privateKey) {
        res.status(200).json({ success: true, message: 'Wallet unlocked.' })
      } else {
        res.status(401).json({ success: false, message: 'Invalid key.' })
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
