import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set()
let isEventListenerCreated = false

// Addresses are compared as values, so they are held in one form. The same account written with
// different capitalisation is the same account, and must not read as a different one.
function normalisedAddress (walletAddress: unknown): string | undefined {
  if (typeof walletAddress !== 'string') return undefined
  const address = walletAddress.trim().toLowerCase()
  return /^0x[0-9a-f]{40}$/.test(address) ? address : undefined
}

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    if (security.authenticatedUsers.from(req) == null) {
      res.status(401).json({ success: false, message: 'Not authenticated' })
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
          const minted = normalisedAddress(minter)
          if (minted !== undefined && !addressesMinted.has(minted)) {
            addressesMinted.add(minted)
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
    if (security.authenticatedUsers.from(req) == null) {
      res.status(401).json({ success: false, message: 'Not authenticated' })
      return
    }
    try {
      // The claim is only worth anything for an address this listener actually saw mint, written
      // in the one form addresses are held in. Anything else is refused rather than compared raw.
      const metamaskAddress = normalisedAddress(req.body.walletAddress)
      if (metamaskAddress !== undefined && addressesMinted.has(metamaskAddress)) {
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
