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

/* The address in the request body is caller-controlled input. It is validated and normalised
   before the server stores it, and only an authenticated customer may register one, so the
   connected-wallet set cannot be stuffed with arbitrary strings by an anonymous caller. */
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/

const normalizedAddress = (value: unknown) => {
  return typeof value === 'string' && ADDRESS_PATTERN.test(value) ? value.toLowerCase() : undefined
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.id) {
      res.status(401).json({ success: false, message: 'You have to be logged in to connect a wallet.' })
      return
    }

    const metamaskAddress = normalizedAddress(req.body?.walletAddress)
    if (!metamaskAddress) {
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
          const culprit = normalizedAddress(exploiter)
          if (culprit && walletsConnected.has(culprit)) {
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
