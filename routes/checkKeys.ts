import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import logger from '../lib/logger'

interface WalletKeyMaterial {
  privateKey: string
  publicKey: string
  address: string
}

/* The wallet holding the shop's Soul Bound Token used to be derived from a BIP-39 seed phrase
   written out as a literal right here (and repeated verbatim in the seeded customer feedback in
   data/static/users.yml). A seed phrase is not a hint or a configuration detail - it is the
   credential itself, because every key the wallet can ever derive follows from it. Anybody who
   read the source tree, a fork, a published container image or the seeded feedback therefore
   held the wallet's private key without ever having been granted access to it.

   Key material is configuration, not code. The phrase is now read from NFT_WALLET_MNEMONIC
   alongside the deployment's other secrets, and a deployment that configures none gets a
   throw-away wallet generated from the platform CSPRNG the first time the endpoint is used.
   That key exists only in this process's memory: it is never written down and it cannot be
   reconstructed from anything that ships with the shop. */
let walletKeyMaterial: Promise<WalletKeyMaterial> | undefined

const throwAwayWallet = async (): Promise<WalletKeyMaterial> => {
  const { Wallet } = await import('ethers')
  const { privateKey, publicKey, address } = Wallet.createRandom()
  return { privateKey, publicKey, address }
}

const soulBoundTokenWallet = async (): Promise<WalletKeyMaterial> => {
  walletKeyMaterial ??= (async () => {
    const configuredPhrase = process.env.NFT_WALLET_MNEMONIC?.trim()
    if (!configuredPhrase) {
      return await throwAwayWallet()
    }
    try {
      const { HDNodeWallet } = await import('ethers')
      const { privateKey, publicKey, address } = HDNodeWallet.fromPhrase(configuredPhrase)
      return { privateKey, publicKey, address }
    } catch {
      logger.warn('NFT_WALLET_MNEMONIC is not a valid BIP-39 seed phrase. Using a throw-away wallet instead.')
      return await throwAwayWallet()
    }
  })()
  return await walletKeyMaterial
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey } = await soulBoundTokenWallet()
      const submittedKey = typeof req.body?.privateKey === 'string' ? req.body.privateKey : ''
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return submittedKey === privateKey
      })
      if (submittedKey === privateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        /* The rejection used to tell the caller whether the value they sent was this wallet's
           address or its public key. That is an oracle over the shop's own key material: it
           confirms candidate values to anyone who can post to this endpoint, and it does so
           without any authentication. A failed submission is now a single answer that reveals
           nothing about the wallet beyond "that is not the key". */
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
