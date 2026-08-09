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

/* NFTMinted is a public log entry, so every address that ever minted is public knowledge. Taking
   a wallet address from a request body and crediting the mint to whoever typed it therefore let
   any visitor claim a mint somebody else had paid for: naming an address is not the same as
   owning it. The caller now has to prove they hold the key for the address they are claiming, by
   signing a message that names it, and the signature is checked against that address here. */
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/

const normalizedAddress = (value: unknown) => {
  return typeof value === 'string' && ADDRESS_PATTERN.test(value) ? value.toLowerCase() : undefined
}

export const mintOwnershipMessage = (walletAddress: string) =>
  `OWASP Juice Shop: I control the wallet ${walletAddress.toLowerCase()} and claim its Honey Pot mint.`

const provesControlOf = async (walletAddress: string, signature: unknown) => {
  if (typeof signature !== 'string' || signature.length === 0) {
    return false
  }
  try {
    const { verifyMessage } = await import('ethers')
    const signer = verifyMessage(mintOwnershipMessage(walletAddress), signature)
    return signer.toLowerCase() === walletAddress
  } catch {
    return false
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
          const minted = normalizedAddress(minter)
          if (minted && !addressesMinted.has(minted)) {
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
  return async (req: Request, res: Response) => {
    try {
      /* A mint is credited to an account, so there has to be one. */
      const user = security.authenticatedUsers.from(req)
      if (!user?.data?.id) {
        res.status(401).json({ success: false, message: 'You have to be logged in to verify a mint.' })
        return
      }

      const metamaskAddress = normalizedAddress(req.body?.walletAddress)
      if (!metamaskAddress) {
        res.status(400).json({ success: false, message: 'A valid wallet address is required.' })
        return
      }

      if (!await provesControlOf(metamaskAddress, req.body?.signature)) {
        res.status(401).json({ success: false, message: 'Sign the verification message with this wallet to prove it is yours.' })
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
