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
      /* The chain listener is an optional integration: it needs an API key and outbound access to
         the Sepolia endpoint, and neither is guaranteed. When it cannot be brought up, that is a
         missing upstream, not a fault in this request - answering 500 turns an unconfigured
         integration into a server error and takes the caller down with it. Report that no listener
         is watching and carry on; the verification step below observes nothing and simply declines,
         which is the correct outcome when no mint can be confirmed. */
      logger.error(`Unable to create the NFT mint listener: ${utils.getErrorMessage(error)}`)
      res.status(200).json({ success: false, message: 'Event Listener unavailable' })
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
