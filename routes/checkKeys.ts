import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

/* The seed phrase of this wallet used to be written out right here in the source. A mnemonic is
   the credential - whoever reads it owns every key the wallet can ever derive - so committing it
   put the wallet in every clone, every fork, every published container image and every search
   result for the phrase. Secrets are configuration, not code: the phrase now comes from the
   environment, and when the operator supplies none the shop derives a throw-away wallet at boot
   so there is nothing left to leak. */
let walletKeys: Promise<{ privateKey: string, publicKey: string, address: string }> | undefined

const soulBoundWallet = async () => {
  if (!walletKeys) {
    walletKeys = (async () => {
      const { HDNodeWallet, Wallet } = await import('ethers')
      const phrase = process.env.NFT_WALLET_MNEMONIC
      const wallet = phrase ? HDNodeWallet.fromPhrase(phrase) : Wallet.createRandom()
      return { privateKey: wallet.privateKey, publicKey: wallet.publicKey, address: wallet.address }
    })()
  }
  return await walletKeys
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await soulBoundWallet()
      const submittedKey = typeof req.body?.privateKey === 'string' ? req.body.privateKey : ''

      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return submittedKey === privateKey
      })
      if (submittedKey === privateKey) {
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
