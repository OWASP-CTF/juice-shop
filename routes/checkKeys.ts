import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import logger from '../lib/logger'
import { challenges } from '../data/datacache'

interface ShopWalletKeys {
  privateKey: string
  publicKey: string
  address: string
}

// The unlock wallet was previously reconstructed on every request from a hardcoded BIP-39
// mnemonic - a phrase that also ended up quoted in plaintext in one of the seeded feedback
// entries. Anyone who read either the source or that feedback comment could derive the exact
// same private key. Instead, mint a fresh keypair the first time it is needed and cache it in
// memory for the life of the process: no mnemonic, seed, or key is ever stored, logged or
// shipped anywhere an attacker could read it back.
let shopWalletKeys: Promise<ShopWalletKeys> | null = null

async function getShopWalletKeys (): Promise<ShopWalletKeys> {
  if (shopWalletKeys === null) {
    shopWalletKeys = import('ethers').then(({ Wallet }) => {
      const generated = Wallet.createRandom()
      return { privateKey: generated.privateKey, publicKey: generated.publicKey, address: generated.address }
    })
  }
  return await shopWalletKeys
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await getShopWalletKeys()
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
      logger.warn(`Could not check the submitted key: ${utils.getErrorMessage(error)}`)
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
