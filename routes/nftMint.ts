import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set<string>()
/* Which account a minting address has been credited to, so a mint cannot be claimed twice or
   claimed by somebody who does not hold the wallet. */
const claimedBy = new Map<string, number>()
let isEventListenerCreated = false

/* A wallet address arriving in a request body is a claim, not a proof. Anything the server is
   willing to act on has to be checked here, on the server: that it is a well-formed address,
   that the caller is a logged-in customer, and that the mint it refers to was actually observed
   on chain for that exact address. */
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/

const normalizedAddress = (value: unknown) => {
  return typeof value === 'string' && ADDRESS_PATTERN.test(value) ? value.toLowerCase() : undefined
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
          const minted = normalizedAddress(minter)
          if (minted && !addressesMinted.has(minted)) {
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
    try {
      /* Minting is credited to an account, so there has to be an account. Without this the
         endpoint hands out a reward to anyone who can name an address. */
      const user = security.authenticatedUsers.from(req)
      if (!user?.data?.id) {
        res.status(401).json({ success: false, message: 'You have to be logged in to verify a mint.' })
        return
      }

      const metamaskAddress = normalizedAddress(req.body?.walletAddress)
      if (!metamaskAddress) {
        res.status(400).json({ success: false, message: 'A valid wallet address is required.' })
        return
      }

      /* An address that has minted is credited to the first account that names it, and stays
         bound to that account. Without this the set is a shared pool: the addresses that minted
         are published on chain, so any signed-in customer could read one off the ledger, present
         it here and be credited for somebody else's mint -- and because the entry was then
         removed, the account that actually owns the address could no longer claim it. */
      const claimant = claimedBy.get(metamaskAddress)
      if (claimant !== undefined && claimant !== user.data.id) {
        res.status(403).json({ success: false, message: 'This wallet address is already associated with another account.' })
        return
      }

      if (addressesMinted.has(metamaskAddress)) {
        claimedBy.set(metamaskAddress, user.data.id)
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
