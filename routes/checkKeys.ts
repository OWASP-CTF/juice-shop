import { type Request, type Response } from 'express'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

export function checkKeys () {
  return (_req: Request, res: Response) => {
    res.status(410).json({ success: false, message: 'Private-key verification is disabled.' })
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
