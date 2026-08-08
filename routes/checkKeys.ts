import { type Request, type Response } from 'express'

export function checkKeys () {
  return async (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'NFT wallet key verification disabled' })
  }
}
export function nftUnlocked () {
  return (_req: Request, res: Response) => {
    res.status(200).json({ status: false })
  }
}
