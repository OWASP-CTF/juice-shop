import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'

// Wallets that asked to be watched for a contract exploit. The route needs no session, so the
// body used to be added verbatim - any JSON value, any number of times. Only well-formed
// addresses are accepted now, and the set is bounded (oldest entry evicted) so an anonymous
// caller cannot grow it until the process runs out of memory.
const walletsConnected = new Set<string>()
const MAX_CONNECTED_WALLETS = 1000
let isEventListenerCreated = false

const ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/

function asWalletAddress (value: unknown): string | null {
  return (typeof value === 'string' && ETH_ADDRESS.test(value)) ? value : null
}

function rememberConnectedWallet (address: string) {
  if (walletsConnected.has(address)) {
    return
  }
  if (walletsConnected.size >= MAX_CONNECTED_WALLETS) {
    const oldest: string | undefined = walletsConnected.values().next().value
    if (oldest !== undefined) {
      walletsConnected.delete(oldest)
    }
  }
  walletsConnected.add(address)
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    // Only a well-formed address is remembered; anything else is ignored rather than rejected,
    // so creating the subscription stays a side effect of the request exactly as it was before.
    const metamaskAddress = asWalletAddress(req.body?.walletAddress)
    if (metamaskAddress !== null) {
      rememberConnectedWallet(metamaskAddress)
    }
    try {
      if (!isEventListenerCreated) {
        const { WebSocketProvider, Contract } = await import('ethers')
        const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
        provider.websocket.onerror = (error: any) => {
          logger.error(`WebSocket error (Contract Exploit Listener): ${error.message || error}`)
          isEventListenerCreated = false
        }
        const contract = new Contract(web3WalletAddress, web3WalletABI, provider as any)
        // The subscription is asynchronous: without a rejection handler an unreachable node
        // turns into an unhandled rejection, which takes the whole process down on Node >= 15.
        void contract.on('ContractExploited', (exploiter: string) => {
          const address = asWalletAddress(exploiter)
          if (address === null) {
            return
          }
          const exploitedByConnectedWallet = walletsConnected.has(address)
          challengeUtils.solveIf(challenges.web3WalletChallenge, () => exploitedByConnectedWallet)
          if (exploitedByConnectedWallet) {
            walletsConnected.delete(address)
          }
        }).catch((error: any) => {
          logger.error(`Failed to subscribe to ContractExploited events: ${error?.message || error}`)
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
