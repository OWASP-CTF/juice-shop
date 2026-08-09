import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

/*
 * The shop's Soul Bound Token wallet was identified by a BIP-39 mnemonic that had leaked twice:
 * as a literal in this file, and quoted verbatim inside a seeded customer feedback that
 * `GET /api/Feedbacks` hands to every anonymous visitor.
 *
 * A mnemonic is not a hint towards the credential, it *is* the credential: every private key the
 * wallet can ever derive follows from it deterministically, so anyone who read either copy owned
 * the wallet outright.
 *
 * OWASP Secrets Management Cheat Sheet, section 9.2 "Remediation", requires all three steps for an
 * exposed secret - Revocation, Rotation and Deletion - and explicitly states that secrets
 * "revoked/rotated must be removed from the exposed system immediately, including secrets
 * discovered in code or logs". Deleting one copy of a published phrase, or keeping the same phrase
 * and merely moving it to configuration, satisfies none of them: the phrase is spent the moment it
 * is published.
 *
 * So the old phrase is retired for good and never reappears anywhere in this repository. The
 * wallet's identity is now configuration, not code (ASVS V6.4.1, V2.10.4): an operator who runs a
 * real wallet supplies its phrase through `NFT_WALLET_MNEMONIC`, which belongs in a key vault or
 * secret store and is read from the process environment here. A deployment that configures nothing
 * gets a wallet freshly derived from the platform CSPRNG at first use, so the default shop holds no
 * long-lived secret that could be leaked in the first place.
 */
interface ShopWalletKeys { privateKey: string, publicKey: string, address: string }

let shopWalletKeys: Promise<ShopWalletKeys> | undefined

async function deriveShopWallet (): Promise<ShopWalletKeys> {
  const { HDNodeWallet } = await import('ethers')
  const configuredMnemonic = process.env.NFT_WALLET_MNEMONIC?.trim()
  const wallet = configuredMnemonic ? HDNodeWallet.fromPhrase(configuredMnemonic) : HDNodeWallet.createRandom()
  return { privateKey: wallet.privateKey, publicKey: wallet.publicKey, address: wallet.address }
}

async function shopWallet (): Promise<ShopWalletKeys> {
  if (!shopWalletKeys) {
    // A misconfigured phrase must not be cached as a permanent failure, so drop the memo and rethrow.
    shopWalletKeys = deriveShopWallet().catch((error) => {
      shopWalletKeys = undefined
      throw error
    })
  }
  return await shopWalletKeys
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { privateKey, publicKey, address } = await shopWallet()
      const submittedKey: string = typeof req.body?.privateKey === 'string' ? req.body.privateKey : ''
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
