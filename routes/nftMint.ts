import { type Request, type Response } from 'express'

/* Both of these endpoints credited an on-chain achievement to whoever asked for it.
   `walletNFTVerify` took a wallet address out of the request body and treated naming it as proof
   of owning it - but NFTMinted is a public log, so every address that ever minted is public
   knowledge, and one visitor's mint could be claimed by any other. `nftMintListener` opened a
   websocket to an external chain provider on demand and never closed it, so an anonymous caller
   could make the shop hold provider connections open indefinitely.

   Neither can be made sound from inside the shop: it cannot observe the chain on a visitor's
   behalf without trusting a claim it has no way to check. The shop stops answering for the chain
   and both endpoints refuse. The Honey Pot itself, the faucet and the contracts are untouched -
   a mint still happens on-chain, where it can be verified by anyone who cares to look. */

export function nftMintListener () {
  return async (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'The shop no longer listens to the chain on a visitor\'s behalf.' })
  }
}

export function walletNFTVerify () {
  return (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'The shop cannot verify ownership of a wallet it was merely told about.' })
  }
}
