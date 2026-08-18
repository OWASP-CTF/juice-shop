import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set<string>()
let isEventListenerCreated = false

const WALLET_ADDRESS_FORMAT = /^0x[0-9a-f]{40}$/

/* Both the mint the chain reports and the mint a caller claims end up being compared to each
   other, so both are reduced to a single canonical spelling first. An address is 20 bytes of
   hex; how it happens to be capitalised carries no meaning, and anything that is not an address
   at all never becomes a key that a lookup could match. */
function canonicalWalletAddress (candidate: unknown): string | null {
  if (typeof candidate !== 'string') {
    return null
  }
  const canonical = candidate.trim().toLowerCase()
  return WALLET_ADDRESS_FORMAT.test(canonical) ? canonical : null
}

/* Neither of these endpoints is public: one spends the shop's own upstream connection, the
   other hands out challenge credit. An anonymous caller gets neither. */
function rejectedAsAnonymous (req: Request, res: Response) {
  if (security.authenticatedUsers.from(req) !== undefined) {
    return false
  }
  res.status(401).json({ success: false, message: 'You have to be logged in to do that.' })
  return true
}

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    if (rejectedAsAnonymous(req, res)) {
      return
    }
    try {
      if (!isEventListenerCreated) {
        const { WebSocketProvider, Contract } = await import('ethers')
        const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
        provider.websocket.onerror = (error: any) => {
          logger.error(`WebSocket error (NFT Mint Listener): ${error.message || error}`)
          isEventListenerCreated = false
        }
        const contract = new Contract(nftAddress, nftABI, provider as any)
        void contract.on('NFTMinted', (minter: string) => {
          const minterAddress = canonicalWalletAddress(minter)
          if (minterAddress !== null) {
            addressesMinted.add(minterAddress)
          }
        })
        isEventListenerCreated = true
      }
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

export function walletNFTVerify () {
  return (req: Request, res: Response) => {
    if (rejectedAsAnonymous(req, res)) {
      return
    }
    try {
      /* Credit is only given for a mint this shop actually watched happen, looked up under the
         one spelling those mints are filed under. A body that is not a wallet address is simply
         an address that never minted, and is turned away on the same path as any other. */
      const metamaskAddress = canonicalWalletAddress(req.body.walletAddress)
      if (metamaskAddress !== null && addressesMinted.has(metamaskAddress)) {
        addressesMinted.delete(metamaskAddress)
        challengeUtils.solveIf(challenges.nftMintChallenge, () => true)
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftMintChallenge })
      } else {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
