import { type Request, type Response } from 'express'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const privateKey = process.env.NFT_CHALLENGE_PRIVATE_KEY
      if (!privateKey) {
        res.status(503).json({ success: false, message: 'NFT verification is not configured' })
        return
      }
      if (req.body.privateKey === privateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        res.status(401).json({ success: false, message: 'Invalid NFT verification key', status: challenges.nftUnlockChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
