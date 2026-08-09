import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set<string>()
let isEventListenerCreated = false

// An address in a request body is a claim about a wallet, never proof of one. Only a well-formed
// address is recorded, and in one casing, so the mint event and the claim can be compared at all.
const walletAddressFrom = (value: unknown) => {
  return typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value) ? value.toLowerCase() : undefined
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
          const minted = walletAddressFrom(minter)
          if (minted !== undefined) {
            addressesMinted.add(minted)
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
      if (!security.authenticatedUsers.from(req)) {
        res.status(401).json({ success: false, message: 'You have to be logged in to verify a mint.' })
        return
      }
      const metamaskAddress = walletAddressFrom(req.body?.walletAddress)
      if (metamaskAddress === undefined) {
        res.status(400).json({ success: false, message: 'A valid wallet address is required.' })
        return
      }
      if (addressesMinted.has(metamaskAddress)) {
        addressesMinted.delete(metamaskAddress)
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
