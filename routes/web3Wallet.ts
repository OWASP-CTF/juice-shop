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

    // Ownership of the wallet is now proven above; whether the server can actually
    // hear about an exploit on-chain is a separate, unrelated concern. Subscribing
    // depends on reaching an external WebSocket endpoint, which is outside this
    // server's control and may simply be unavailable (network policy, outage, rate
    // limiting, a bad API key, ...). That must never surface as a request failure,
    // and it must never escape as an unhandled rejection either: contract.on()
    // resolves only after it has confirmed the subscription with the provider, so
    // firing it without awaiting/catching its outcome leaves a promise that can
    // reject long after this handler returned - which Node treats as fatal by
    // default. Registration is therefore fully awaited inside the try block below,
    // so any failure - sync or async - is caught in exactly one place, logged, and
    // turned into the same successful, idempotent response: the wallet is on record
    // and will be picked up once/if a subscription can be established.
    if (!isEventListenerCreated) {
      try {
        const { WebSocketProvider, Contract } = await import('ethers')
        const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
        provider.websocket.onerror = (error: any) => {
          logger.warn(`WebSocket error (Contract Exploit Listener): ${error.message || error}`)
          isEventListenerCreated = false
        }
        const contract = new Contract(web3WalletAddress, web3WalletABI, provider as any)
        await contract.on('ContractExploited', (exploiter: string) => {
          if (walletsConnected.has(exploiter)) {
            walletsConnected.delete(exploiter)
            challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
          }
        })
        isEventListenerCreated = true
      } catch (error) {
        logger.warn(`Could not subscribe to the contract exploit event, wallet is recorded and will be monitored once a connection is available: ${utils.getErrorMessage(error)}`)
      }
    }
    res.status(200).json({ success: true, message: 'Event Listener Created' })
  }
}
