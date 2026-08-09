import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/
/* Only ever filled from the on-chain "NFTMinted" event log, never from a request body. */
const addressesMinted = new Set<string>()
/* One verified mint per account, so a single user cannot claim an unlimited
   number of foreign minter addresses. */
const usersVerified = new Set<number>()
let isEventListenerCreated = false

/* Rejects anything that is not a syntactically valid EVM address and normalises
   the casing, so lookups cannot be desynchronised by checksum capitalisation. */
function toWalletAddress (address: unknown): string | null {
  if (typeof address !== 'string') {
    return null
  }
  const trimmed = address.trim()
  return EVM_ADDRESS.test(trimmed) ? trimmed.toLowerCase() : null
}

export function nftMintListener () {
  return async (req: Request, res: Response) => {
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
          const mintedBy = toWalletAddress(minter)
          if (mintedBy !== null) {
            addressesMinted.add(mintedBy)
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
    try {
      const metamaskAddress = toWalletAddress(req.body?.walletAddress)
      if (metamaskAddress === null) {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
        return
      }
      /* Claiming a mint is a state-changing operation: it needs an authenticated
         session, the identity of which is taken from the JWT and never from the
         request body. */
      const loggedInUser = security.authenticatedUsers.from(req)
      if (loggedInUser == null) {
        res.status(401).json({ success: false, message: 'Authentication required to verify a minted NFT', status: challenges.nftMintChallenge })
        return
      }
      const userId = loggedInUser.data.id
      if (usersVerified.has(userId)) {
        res.status(403).json({ success: false, message: 'A minted NFT has already been verified for this account', status: challenges.nftMintChallenge })
        return
      }
      /* The mint itself is confirmed against the server-side event log only. */
      if (!addressesMinted.has(metamaskAddress)) {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
        return
      }
      addressesMinted.delete(metamaskAddress)
      usersVerified.add(userId)
      challengeUtils.solveIf(challenges.nftMintChallenge, () => true)
      res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftMintChallenge })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
