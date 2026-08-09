import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const EVM_ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/
const addressesMinted = new Set<string>()
let isEventListenerCreated = false

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
          addressesMinted.add(minter.toLowerCase())
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
      const metamaskAddress = req.body?.walletAddress
      if (typeof metamaskAddress !== 'string' || !EVM_ADDRESS_PATTERN.test(metamaskAddress)) {
        res.status(400).json({ success: false, message: 'Invalid wallet address' })
        return
      }
      const hasMinted = addressesMinted.delete(metamaskAddress.toLowerCase())
      res.status(200).json({
        success: hasMinted,
        message: hasMinted ? 'Wallet minted the NFT' : 'Wallet did not mint the NFT',
        status: challenges.nftMintChallenge
      })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
