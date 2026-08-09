import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function logout () {
  return (req: Request, res: Response) => {
    security.revoke(utils.jwtFrom(req))
    res.clearCookie('token').sendStatus(204)
  }
}
