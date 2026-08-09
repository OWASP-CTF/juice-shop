import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'

// Addresses observed minting the honey pot on-chain. Two things guard this set now:
// nothing that is not a well-formed Ethereum address can get in or be looked up (the verify
// route is unauthenticated, so it used to take any JSON value straight from the wire), and the
// set is bounded so a stream of chain events cannot grow it without limit.
const addressesMinted = new Set<string>()
const MAX_TRACKED_MINTERS = 1000
let isEventListenerCreated = false

const ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/

function asWalletAddress (value: unknown): string | null {
  return (typeof value === 'string' && ETH_ADDRESS.test(value)) ? value : null
}

function rememberMinter (minter: unknown) {
  const address = asWalletAddress(minter)
  if (address === null || addressesMinted.has(address)) {
    return
  }
  if (addressesMinted.size >= MAX_TRACKED_MINTERS) {
    const oldest: string | undefined = addressesMinted.values().next().value
    if (oldest !== undefined) {
      addressesMinted.delete(oldest)
    }
  }
  addressesMinted.add(address)
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
        // The subscription is asynchronous: without a rejection handler an unreachable node
        // turns into an unhandled rejection, which takes the whole process down on Node >= 15.
        void contract.on('NFTMinted', (minter: string) => {
          rememberMinter(minter)
        }).catch((error: any) => {
          logger.error(`Failed to subscribe to NFTMinted events: ${error?.message || error}`)
          isEventListenerCreated = false
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
      const metamaskAddress = asWalletAddress(req.body?.walletAddress)
      if (metamaskAddress === null) {
        res.status(400).json({ success: false, message: 'A valid Ethereum wallet address is required', status: challenges.nftMintChallenge })
        return
      }
      // The proof is the on-chain mint, so it is the predicate the challenge is scored on as
      // well as the gate on the response - the route must never confirm a mint it did not see.
      const mintedByThisWallet = addressesMinted.has(metamaskAddress)
      challengeUtils.solveIf(challenges.nftMintChallenge, () => mintedByThisWallet)
      if (mintedByThisWallet) {
        addressesMinted.delete(metamaskAddress)
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftMintChallenge })
      } else {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
