import { type Request, type Response } from 'express'

/* This endpoint let any unauthenticated caller add a wallet address of their choosing to a
   server-side set and open an outbound websocket to an external chain provider, which is both an
   unbounded resource the caller controls and a claim over an address they never proved they own.
   The wallet's own contract no longer has the reentrancy flaw this was listening for, so the
   listener is gone and the route refuses. */

export function contractExploitListener () {
  return async (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'Web3 wallet exploit listener disabled' })
  }
}
