import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

/* The Soul Bound Token wallet is shop property, so talking about its keys is a privilege of
   accounts this shop has issued a session to. Served to anybody, the key check below is an oracle:
   its three distinct answers tell an unauthenticated passer-by whether a value they are holding is
   the wallet's address, its public key or neither, and the unlock state of the wallet could be read
   just as freely. Both endpoints of the feature ask the same question about the same wallet, so
   both are gated - the pages and the endpoints stay in place, they just require a caller who was
   granted access first. */
function grantedAccessToWallet (req: Request) {
  const token = utils.jwtFrom(req)
  if (!token || !security.verify(token)) {
    return false
  }
  return security.authenticatedUsers.get(token)?.data?.id !== undefined
}

function denyAccessToWallet (res: Response) {
  res.status(401).json({ success: false, message: 'You have to be logged in to access this wallet.' })
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    if (!grantedAccessToWallet(req)) {
      denyAccessToWallet(res)
      return
    }
    try {
      const { HDNodeWallet } = await import('ethers')
      const mnemonic = 'purpose betray marriage blame crunch monitor spin slide donate sport lift clutch'
      const mnemonicWallet = HDNodeWallet.fromPhrase(mnemonic)
      const privateKey = mnemonicWallet.privateKey
      const publicKey = mnemonicWallet.publicKey
      const address = mnemonicWallet.address
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return req.body.privateKey === privateKey
      })
      if (req.body.privateKey === privateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (req.body.privateKey === address) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (req.body.privateKey === publicKey) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else {
          res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
        }
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    if (!grantedAccessToWallet(req)) {
      denyAccessToWallet(res)
      return
    }
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
