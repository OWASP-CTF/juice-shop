import { type Request, type Response } from 'express'

export function contractExploitListener () {
  return async (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'Web3 wallet exploit listener disabled' })
  }
}
