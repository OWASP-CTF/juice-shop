import crypto from 'node:crypto'
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

const NONCE_LIFETIME_IN_MS = 5 * 60 * 1000
/* One outstanding challenge string per account. It is single use and short lived, so a
   captured signature cannot be replayed and one account cannot spend another's nonce. */
const ownershipNonces = new Map<number, { nonce: string, expiresAt: number }>()

function issueNonce (userId: number) {
  const nonce = crypto.randomBytes(32).toString('hex')
  ownershipNonces.set(userId, { nonce, expiresAt: Date.now() + NONCE_LIFETIME_IN_MS })
  return nonce
}

function consumeNonce (userId: number) {
  const issued = ownershipNonces.get(userId)
  ownershipNonces.delete(userId)
  return issued !== undefined && issued.expiresAt > Date.now() ? issued.nonce : null
}

/* Confirms the caller controls the private key behind the address, rather than taking its
   word for it. Anything that fails to verify yields null so the caller is treated as
   owning no address at all. */
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

/* Reads the mint straight from the contract instead of relying on an event the process may
   never have seen. With no reachable node this throws and the caller is refused. */
async function hasMintedOnChain (address: string) {
  const { JsonRpcProvider, Contract } = await import('ethers')
  const rpcUrl = process.env.ETH_RPC_URL ?? `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`
  const contract = new Contract(nftAddress, nftABI, new JsonRpcProvider(rpcUrl))
  return BigInt(await contract.balanceOf(address)) > 0n
}

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser?.data?.id) {
      res.status(401).json({ success: false, message: 'Unauthorized' })
      return
    }
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
          if (!addressesMinted.has(minter)) {
            addressesMinted.add(minter)
          }
        })
        isEventListenerCreated = true
      }
      res.status(200).json({ success: true, message: 'Event Listener Created', nonce: issueNonce(loggedInUser.data.id) })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

export function walletNFTVerify () {
  return async (req: Request, res: Response) => {
    try {
      const loggedInUser = security.authenticatedUsers.from(req)
      if (!loggedInUser?.data?.id) {
        res.status(401).json({ success: false, message: 'Unauthorized' })
        return
      }

      // Which address minted is a fact about the chain, not a claim the client gets to make.
      // It is only accepted once the caller has proven control of the address and the mint is
      // confirmed against the contract; every failure path denies.
      const nonce = consumeNonce(loggedInUser.data.id)
      const provenAddress = nonce !== null ? await addressProvenBySignature(nonce, req.body.signature) : null
      const claimedAddress = typeof req.body.walletAddress === 'string' ? req.body.walletAddress : ''
      const ownsClaimedAddress = provenAddress !== null && provenAddress.toLowerCase() === claimedAddress.toLowerCase()

      let minted = false
      if (ownsClaimedAddress) {
        try {
          minted = addressesMinted.has(provenAddress) || await hasMintedOnChain(provenAddress)
        } catch (error) {
          logger.warn(`Could not confirm the NFT mint on chain: ${utils.getErrorMessage(error)}`)
          minted = false
        }
      }

      if (minted) {
        addressesMinted.delete(provenAddress as string)
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
