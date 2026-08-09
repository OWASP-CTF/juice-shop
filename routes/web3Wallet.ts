import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletsConnected = new Set<string>()
let isEventListenerCreated = false

// An address in a request body is a claim about a wallet, never proof of one. Only a well-formed
// address is watched, and in one casing, so the event and the claim can be compared at all.
const walletAddressFrom = (value: unknown) => {
  return typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value) ? value.toLowerCase() : undefined
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    if (!security.authenticatedUsers.from(req)) {
      res.status(401).json({ success: false, message: 'You have to be logged in to connect a wallet.' })
      return
    }
    const metamaskAddress = walletAddressFrom(req.body?.walletAddress)
    if (metamaskAddress === undefined) {
      res.status(400).json({ success: false, message: 'A valid wallet address is required.' })
      return
    }
    walletsConnected.add(metamaskAddress)
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
          const culprit = walletAddressFrom(exploiter)
          if (culprit !== undefined && walletsConnected.has(culprit)) {
            walletsConnected.delete(culprit)
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
