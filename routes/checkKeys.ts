import crypto from 'node:crypto'
import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

interface ShopWallet { privateKey: string, publicKey: string, address: string }

// A seed phrase in the source hands its private key to every reader of the source. The phrase is
// configuration: the operator supplies it, and a shop that was given none mints a throw-away
// wallet at startup rather than falling back on a value anybody could look up.
let shopWallet: Promise<ShopWallet> | undefined

const walletOfTheShop = async (): Promise<ShopWallet> => {
  shopWallet ??= import('ethers').then(({ HDNodeWallet, Mnemonic, Wallet }) => {
    const phrase = process.env.NFT_WALLET_MNEMONIC?.trim()
    const node = phrase ? HDNodeWallet.fromMnemonic(Mnemonic.fromPhrase(phrase)) : Wallet.createRandom()
    return { privateKey: node.privateKey, publicKey: node.publicKey, address: node.address }
  })
  return await shopWallet
}

// String equality returns as soon as two characters differ, so the time a guess takes to be
// refused says how much of the key was right. A key can be recovered a character at a time from
// that alone, which is why every comparison against the wallet is length-checked and constant time.
const sameSecret = (submitted: string, secret: string) => {
  const given = Buffer.from(submitted, 'utf8')
  const expected = Buffer.from(secret, 'utf8')
  return given.length === expected.length && crypto.timingSafeEqual(given, expected)
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await walletOfTheShop()
      const submitted = typeof req.body?.privateKey === 'string' ? req.body.privateKey : ''
      const unlocked = sameSecret(submitted, privateKey)

      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => unlocked)
      if (unlocked) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (sameSecret(submitted, address)) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (sameSecret(submitted, publicKey)) {
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
