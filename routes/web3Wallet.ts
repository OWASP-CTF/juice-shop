import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletsConnected = new Set()
let isEventListenerCreated = false

export function walletOwnershipMessage (walletAddress: string) {
  return `Verify ownership of wallet ${walletAddress} to monitor it for the Wallet Depletion challenge`
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = req.body.walletAddress
    const signature = req.body.signature

    // Merely naming a wallet address (e.g. one seen exploiting the contract
    // in the public on-chain event log) must not be enough to get credit
    // for it. The caller has to prove they actually control that wallet by
    // signing a challenge message with its private key, otherwise anyone
    // could watch the chain for someone else's genuine exploit and claim
    // it as their own by just POSTing that address here.
    if (typeof metamaskAddress !== 'string' || typeof signature !== 'string') {
      res.status(400).json({ success: false, message: 'walletAddress and signature are required' })
      return
    }
    try {
      const { verifyMessage } = await import('ethers')
      const recoveredAddress = verifyMessage(walletOwnershipMessage(metamaskAddress), signature)
      if (recoveredAddress.toLowerCase() !== metamaskAddress.toLowerCase()) {
        res.status(400).json({ success: false, message: 'Wallet ownership could not be verified' })
        return
      }
    } catch (error) {
      res.status(400).json({ success: false, message: 'Wallet ownership could not be verified' })
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
