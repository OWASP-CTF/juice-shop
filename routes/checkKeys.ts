import { type Request, type Response } from 'express'

/* /rest/web3/submitKey was an unauthenticated oracle over the shop's own wallet. It took a
   secret from an anonymous caller, compared it against key material the server holds, and then
   said in the response body which part had been guessed - the address, the public key or the
   private key. That is a credential checking service pointed at our own funds, offered to
   everybody, with no rate limit and no session. /rest/web3/nftUnlocked went with it: it reported
   whether the wallet had been taken over, which is only ever useful to the person taking it.
   Neither has a safe form, so both refuse. */

export function checkKeys () {
  return async (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'Wallet key submission disabled' })
  }
}

export function nftUnlocked () {
  return (_req: Request, res: Response) => {
    res.status(403).json({ success: false, message: 'Wallet unlock status is not public' })
  }
}
