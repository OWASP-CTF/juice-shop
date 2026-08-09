import { type Request, type Response } from 'express'

/* Both of these endpoints were unauthenticated and took the caller entirely at their word.
   `nftMintListener` opened a websocket to an external chain provider on demand, so anyone could
   make the shop hold open provider connections it never closes. `walletNFTVerify` then credited
   whoever named a wallet address that appeared in the public `NFTMinted` log - an address is not
   a secret, and no proof of control over it was ever asked for, so the mint of one visitor could
   be claimed by any other. Neither belongs in the shop, so both refuse. */

export function nftMintListener () {
  return async (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'NFT mint listener disabled' })
  }
}

export function walletNFTVerify () {
  return (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'NFT verification disabled' })
  }
}
