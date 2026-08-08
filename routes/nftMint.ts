import { type Request, type Response } from 'express'

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
