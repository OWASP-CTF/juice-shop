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

/* Both endpoints below act on a wallet address that arrives in a request. An address in a request
   is a claim, not a proof of ownership, and neither endpoint asked who was making it: one opened a
   subscription that decides who gets credited for a mint, the other handed out the credit. A mint
   is attributed to an account, so there has to be an account behind the request - and the address
   has to be an address before the server stores or compares it. */
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/

const normalizedAddress = (value: unknown) => {
  return typeof value === 'string' && ADDRESS_PATTERN.test(value) ? value.toLowerCase() : undefined
}

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    /* Subscribing the shop to on-chain mint events decides who the shop will later credit, so it
       is not an anonymous action. Without this the subscription - and the set of addresses it
       fills - could be driven by anyone who could reach the endpoint. */
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.id) {
      res.status(401).json({ success: false, message: 'You have to be logged in to watch for a mint.' })
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

      if (addressesMinted.has(metamaskAddress)) {
        /* The credit is consumed, so one observed mint is worth one reward */
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
