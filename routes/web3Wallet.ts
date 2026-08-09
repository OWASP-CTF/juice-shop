import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletsConnected = new Set<string>()
let isEventListenerCreated = false

// Only a well-formed Ethereum address is ever recorded as "connected", and addresses are
// compared case-insensitively so a checksum-cased and a lowercase submission of the same
// address are not treated as two different wallets.
const ETH_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/

function normalizeAddress (value: unknown): string | undefined {
  return typeof value === 'string' && ETH_ADDRESS_PATTERN.test(value) ? value.toLowerCase() : undefined
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    // Registering an arbitrary caller-supplied address without any session behind it would
    // let anyone piggyback on an exploit performed by a different wallet.
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      res.status(401).json({ success: false, message: 'You have to be logged in to connect a wallet.' })
      return
    }

    const metamaskAddress = normalizeAddress(req.body?.walletAddress)
    if (metamaskAddress === undefined) {
      res.status(400).json({ success: false, message: 'A valid Ethereum wallet address is required.' })
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
          const culprit = normalizeAddress(exploiter)
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
