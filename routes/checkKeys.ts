import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

let sbtWallet: any

/*
 * The wallet backing the Soul Bound Token must never have its secret material in
 * the source tree. It is taken from the environment and, when none is provided,
 * a fresh random wallet is generated per boot so that nothing recoverable from
 * the repository can unlock it.
 */
async function getSbtWallet () {
  if (!sbtWallet) {
    const { HDNodeWallet, Mnemonic } = await import('ethers')
    const phrase = process.env.SBT_WALLET_MNEMONIC
    sbtWallet = phrase
      ? HDNodeWallet.fromMnemonic(Mnemonic.fromPhrase(phrase))
      : HDNodeWallet.createRandom()
  }
  return sbtWallet
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const mnemonicWallet = await getSbtWallet()
      const privateKey = mnemonicWallet.privateKey
      const publicKey = mnemonicWallet.publicKey
      const address = mnemonicWallet.address
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
