import { type Request, type Response } from 'express'
import { randomBytes } from 'node:crypto'
import { getAddress, isAddress, verifyMessage } from 'ethers'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set()
const walletProofs = new Map<string, { address: string, expiresAt: number }>()
let isEventListenerCreated = false

export function createWalletProof (walletAddress: string) {
  if (!isAddress(walletAddress)) return null

  const nonce = randomBytes(32).toString('hex')
  const address = getAddress(walletAddress)
  const expiresAt = Date.now() + 5 * 60 * 1000
  walletProofs.set(nonce, { address, expiresAt })
  return { nonce, message: `Juice Shop NFT mint verification: ${nonce}` }
}

export function verifyWalletProof (walletAddress: string, nonce: string, signature: string) {
  const proof = walletProofs.get(nonce)
  if (!proof || proof.expiresAt < Date.now() || !isAddress(walletAddress)) {
    walletProofs.delete(nonce)
    return false
  }

  try {
    const signer = getAddress(verifyMessage(`Juice Shop NFT mint verification: ${nonce}`, signature))
    if (proof.address !== getAddress(walletAddress) || proof.address !== signer) return false
    walletProofs.delete(nonce)
    return true
  } catch {
    return false
  }
}

export function walletNFTProof () {
  return (req: Request, res: Response) => {
    const proof = createWalletProof(req.body.walletAddress)
    if (!proof) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
    res.status(200).json({ success: true, ...proof })
  }
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
          const address = getAddress(minter)
          if (!addressesMinted.has(address)) {
            addressesMinted.add(address)
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

export function walletNFTVerify () {
  return (req: Request, res: Response) => {
    try {
      const metamaskAddress = req.body.walletAddress
      const address = isAddress(metamaskAddress) ? getAddress(metamaskAddress) : metamaskAddress
      if (verifyWalletProof(address, req.body.nonce, req.body.signature) && addressesMinted.has(address)) {
        addressesMinted.delete(address)
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
