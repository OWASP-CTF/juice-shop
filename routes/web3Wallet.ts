import { type Request, type Response } from 'express'
import { randomBytes } from 'node:crypto'
import { getAddress, isAddress, verifyMessage } from 'ethers'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletsConnected = new Set()
const exploitProofs = new Map<string, { address: string, expiresAt: number }>()
let isEventListenerCreated = false

export function createWalletExploitProof (walletAddress: string) {
  if (!isAddress(walletAddress)) return null

  const nonce = randomBytes(32).toString('hex')
  const address = getAddress(walletAddress)
  exploitProofs.set(nonce, { address, expiresAt: Date.now() + 5 * 60 * 1000 })
  return { nonce, message: `Juice Shop wallet exploit verification: ${nonce}` }
}

export function verifyWalletExploitProof (walletAddress: string, nonce: string, signature: string) {
  const proof = exploitProofs.get(nonce)
  if (!proof || proof.expiresAt < Date.now() || !isAddress(walletAddress)) {
    exploitProofs.delete(nonce)
    return false
  }

  try {
    const signer = getAddress(verifyMessage(`Juice Shop wallet exploit verification: ${nonce}`, signature))
    if (proof.address !== getAddress(walletAddress) || proof.address !== signer) return false
    exploitProofs.delete(nonce)
    return true
  } catch {
    return false
  }
}

export function walletExploitProof () {
  return (req: Request, res: Response) => {
    const proof = createWalletExploitProof(req.body.walletAddress)
    if (!proof) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
    res.status(200).json({ success: true, ...proof })
  }
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = req.body.walletAddress
    const address = isAddress(metamaskAddress) ? getAddress(metamaskAddress) : metamaskAddress
    if (!verifyWalletExploitProof(address, req.body.nonce, req.body.signature)) {
      res.status(401).json({ success: false, message: 'Wallet ownership proof failed' })
      return
    }
    walletsConnected.add(address)
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
          const address = getAddress(exploiter)
          if (walletsConnected.has(address)) {
            walletsConnected.delete(address)
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
