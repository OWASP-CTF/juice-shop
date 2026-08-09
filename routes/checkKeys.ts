import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

// The wallet guarding this challenge used to be derived from a seed phrase written directly
// into the source, which is exactly as good as publishing the private key itself - anyone
// reading the repository (or a clone, fork, container image, or search index of it) owns the
// wallet outright. A mnemonic is a credential, not a fixture, so it belongs in configuration
// that the operator controls, not in version control. When none is configured, a fresh wallet
// is generated once at process start so there is no shared secret to leak in the first place.
let soulBoundWalletPromise: Promise<{ privateKey: string, publicKey: string, address: string }> | undefined

async function soulBoundWallet () {
  if (soulBoundWalletPromise === undefined) {
    soulBoundWalletPromise = (async () => {
      const { HDNodeWallet, Wallet } = await import('ethers')
      const configuredPhrase = process.env.NFT_UNLOCK_WALLET_MNEMONIC
      const wallet = configuredPhrase ? HDNodeWallet.fromPhrase(configuredPhrase) : Wallet.createRandom()
      return { privateKey: wallet.privateKey, publicKey: wallet.publicKey, address: wallet.address }
    })()
  }
  return await soulBoundWalletPromise
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
