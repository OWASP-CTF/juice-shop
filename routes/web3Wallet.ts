import crypto from 'node:crypto'
import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletsConnected = new Set<string>()
let isEventListenerCreated = false

const NONCE_LIFETIME_IN_MS = 5 * 60 * 1000
/* One outstanding challenge string per account, single use and short lived, so a captured
   signature cannot be replayed and one account cannot spend another's nonce. */
const ownershipNonces = new Map<number, { nonce: string, expiresAt: number }>()

export function web3WalletNonce () {
  return (req: Request, res: Response) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser?.data?.id) {
      res.status(401).json({ success: false, message: 'Unauthorized' })
      return
    }
    const nonce = crypto.randomBytes(32).toString('hex')
    ownershipNonces.set(loggedInUser.data.id, { nonce, expiresAt: Date.now() + NONCE_LIFETIME_IN_MS })
    res.status(200).json({ success: true, nonce })
  }
}

/* Confirms the caller controls the private key behind the address instead of taking its word
   for it. Anything that fails to verify yields null, so the caller owns no address at all. */
async function addressProvenBySignature (nonce: string, signature: unknown) {
  if (typeof signature !== 'string' || signature.length === 0) {
    return null
  }
  try {
    const { verifyMessage } = await import('ethers')
    return verifyMessage(nonce, signature)
  } catch {
    return null
  }
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser?.data?.id) {
      res.status(401).json({ success: false, message: 'Unauthorized' })
      return
    }

    // Registering an address is an assertion about a key the caller must actually hold, so it
    // is only recorded against a signature over a nonce this server issued. Without that proof
    // nothing is remembered and, because the challenge is resolved solely from an on-chain
    // event observed for a registered address, nothing can be claimed either.
    const issued = ownershipNonces.get(loggedInUser.data.id)
    ownershipNonces.delete(loggedInUser.data.id)
    const nonce = issued !== undefined && issued.expiresAt > Date.now() ? issued.nonce : null
    const provenAddress = nonce !== null ? await addressProvenBySignature(nonce, req.body.signature) : null
    const claimedAddress = typeof req.body.walletAddress === 'string' ? req.body.walletAddress : ''
    if (provenAddress === null || provenAddress.toLowerCase() !== claimedAddress.toLowerCase()) {
      res.status(400).json({ success: false, message: 'Ownership of the wallet address could not be proven' })
      return
    }
    walletsConnected.add(provenAddress)

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
          if (walletsConnected.has(exploiter)) {
            walletsConnected.delete(exploiter)
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
