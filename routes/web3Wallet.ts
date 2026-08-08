import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/
/* Wallet addresses registered by an authenticated user, keyed by user id so an
   address can never be attributed to somebody else's account. */
const walletsConnected = new Map<string, number>()
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

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = toWalletAddress(req.body?.walletAddress)
    if (metamaskAddress !== null) {
      /* Binding a wallet address is a state-changing operation: it needs an
         authenticated session, the identity of which is taken from the JWT and
         never from the request body. */
      const loggedInUser = security.authenticatedUsers.from(req)
      if (loggedInUser == null) {
        res.status(401).json({ success: false, message: 'Authentication required to register a wallet address' })
        return
      }
      const userId = loggedInUser.data.id
      /* An address already claimed by another account stays with that account. */
      const owner = walletsConnected.get(metamaskAddress)
      if (owner !== undefined && owner !== userId) {
        res.status(403).json({ success: false, message: 'Wallet address is already registered to another account' })
        return
      }
      walletsConnected.set(metamaskAddress, userId)
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
        void contract.on('ContractExploited', (exploiter: string) => {
          const exploiterAddress = toWalletAddress(exploiter)
          if (exploiterAddress !== null && walletsConnected.has(exploiterAddress)) {
            walletsConnected.delete(exploiterAddress)
            challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
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
