import crypto from 'node:crypto'
import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

/* The wallet's recovery phrase is a secret and must not live in the source tree, where every
   reader of the repository - and every consumer of the shipped bundle - is handed it. It is
   supplied through the environment; when no phrase is configured a fresh random one is
   generated at startup so that the wallet is never protected by a value anybody can look up. */
function walletMnemonic () {
  const configuredMnemonic = process.env.NFT_WALLET_MNEMONIC
  return configuredMnemonic && configuredMnemonic.trim().length > 0 ? configuredMnemonic.trim() : null
}

let derivedWallet: { privateKey: string, publicKey: string, address: string } | null = null

async function wallet () {
  if (derivedWallet === null) {
    const { HDNodeWallet, Wallet, Mnemonic } = await import('ethers')
    const mnemonic = walletMnemonic()
    const node = mnemonic !== null
      ? HDNodeWallet.fromMnemonic(Mnemonic.fromPhrase(mnemonic))
      : Wallet.createRandom()
    derivedWallet = { privateKey: node.privateKey, publicKey: node.publicKey, address: node.address }
  }
  return derivedWallet
}

/* Compares two secrets without leaking, through timing, how far a guess got. */
function matches (candidate: string, expected: string) {
  const given = Buffer.from(candidate, 'utf8')
  const target = Buffer.from(expected, 'utf8')
  return given.length === target.length && crypto.timingSafeEqual(given, target)
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await wallet()
      const submittedKey = typeof req.body.privateKey === 'string' ? req.body.privateKey : ''
      const isPrivateKey = matches(submittedKey, privateKey)

      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => isPrivateKey)

      if (isPrivateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (matches(submittedKey, address)) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (matches(submittedKey, publicKey)) {
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
