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

const ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/

/* Ethereum addresses travel in two spellings: the EIP-55 mixed-case form a wallet shows the
   user, and the all-lowercase form. The same account can therefore arrive here written one way
   and come out of a decoded log written the other, so every address is reduced to one canonical
   spelling before it is stored or looked up. Anything that is not an address at all is rejected
   outright rather than stored, which keeps the watch list free of arbitrary caller-supplied
   strings. */
function canonicalAddress (value: unknown): string | undefined {
  return typeof value === 'string' && ETH_ADDRESS.test(value) ? value.toLowerCase() : undefined
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    /* Registering an address is what later entitles it to the challenge credit, so it must
       belong to somebody. Without a session behind the request the watch list is a public
       drop box: anyone could enrol an address they merely read out of the public event log
       and collect on the next exploit that address performs. Tying registration to a logged
       in user makes the entry attributable instead of anonymous. */
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.id) {
      res.status(401).json({ success: false, message: 'You have to be logged in to register a wallet.' })
      return
    }

    const metamaskAddress = canonicalAddress(req.body?.walletAddress)
    if (metamaskAddress === undefined) {
      res.status(400).json({ success: false, message: 'A valid wallet address is required.' })
      return
    }

    walletsConnected.add(metamaskAddress)

    /* Whether the server can actually hear about an exploit on chain is a separate concern from
       accepting the registration. Subscribing depends on reaching an external WebSocket endpoint
       that is outside this server's control and may simply be unavailable (network policy,
       outage, rate limiting, a missing API key, ...). That must not surface as a request failure,
       and it must not escape as an unhandled rejection either: contract.on() settles only once
       the provider has confirmed the subscription, so firing it without awaiting its outcome
       leaves a promise that can reject long after this handler returned. Registration is
       therefore awaited inside the try block, so every failure - synchronous or not - is caught
       in one place, logged, and turned into the same idempotent success response. */
    if (!isEventListenerCreated) {
      try {
        const { WebSocketProvider, Contract } = await import('ethers')
        const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
        provider.websocket.onerror = (error: any) => {
          logger.warn(`WebSocket error (Contract Exploit Listener): ${error.message || error}`)
          isEventListenerCreated = false
        }
        const contract = new Contract(web3WalletAddress, web3WalletABI, provider as any)
        /* The credit is granted on what the server itself observed on chain, never on what the
           caller claims to have done: only an exploiter named by the contract's own event, and
           only one that was registered beforehand, solves the challenge. The registration is
           consumed so a single observed exploit can be cashed in exactly once. */
        await contract.on('ContractExploited', (exploiter: string) => {
          const culprit = canonicalAddress(exploiter)
          if (culprit !== undefined && walletsConnected.delete(culprit)) {
            challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
          }
        })
        isEventListenerCreated = true
      } catch (error) {
        logger.warn(`Could not subscribe to the contract exploit event, the wallet is recorded and will be monitored once a connection is available: ${utils.getErrorMessage(error)}`)
      }
    }

    res.status(200).json({ success: true, message: 'Event Listener Created' })
  }
}
