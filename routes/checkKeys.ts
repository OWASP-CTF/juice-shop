import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

interface WalletKeys {
  privateKey: string
  publicKey: string
  address: string
}

/*
 * A BIP-39 seed phrase is not a piece of configuration that merely unlocks a wallet, it *is* the
 * wallet: every key it can ever derive follows from those twelve words. Writing one into a tracked
 * file therefore hands the wallet to everyone who clones the repository, mirrors it, pulls a
 * published image built from it or simply searches the web for the phrase - and no later edit can
 * take that back, because the phrase stays readable in the history.
 *
 * The endpoint below only ever needs the *derived* keys, to compare them against whatever a visitor
 * submits, so the phrase itself belongs in the deployment's environment next to the other secrets:
 * set NFT_WALLET_MNEMONIC to use a specific wallet. When it is unset - which is the case for a
 * plain checkout - a throwaway wallet is generated in memory on first use, so a default install
 * carries no long-lived secret at all and there is nothing left in the source tree to leak.
 */
let pendingWalletKeys: Promise<WalletKeys> | null = null

async function deriveWalletKeys (): Promise<WalletKeys> {
  const { HDNodeWallet, Wallet } = await import('ethers')
  const configuredMnemonic = process.env.NFT_WALLET_MNEMONIC?.trim()
  const wallet = configuredMnemonic ? HDNodeWallet.fromPhrase(configuredMnemonic) : Wallet.createRandom()
  return { privateKey: wallet.privateKey, publicKey: wallet.publicKey, address: wallet.address }
}

async function walletKeys (): Promise<WalletKeys> {
  // Derived once and reused, so that the generated wallet stays stable for the lifetime of the process.
  pendingWalletKeys ??= deriveWalletKeys()
  try {
    return await pendingWalletKeys
  } catch (error) {
    pendingWalletKeys = null // a misconfigured phrase must not poison every later request
    throw error
  }
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await walletKeys()
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
