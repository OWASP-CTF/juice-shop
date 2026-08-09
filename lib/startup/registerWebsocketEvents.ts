/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Server } from 'socket.io'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: SocketIOClientStatic & Server
}

/* The socket channel is an unauthenticated, client-driven message bus: anything a browser can
   emit, so can any other client. It is therefore never used as evidence that a payload really
   reached a dangerous sink - the search term is bound as text by the search result component,
   so there is no client-side script execution left to report. */
const registerWebsocketEvents = (server: any) => {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  // @ts-expect-error FIXME Type safety issue when setting global socket-io object
  globalWithSocketIO.io = io

  io.on('connection', (socket: any) => {
    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    notifications.forEach((notification: any) => {
      socket.emit('challenge solved', notification)
    })

    socket.on('notification received', (data: any) => {
      const i = notifications.findIndex(({ flag }: any) => flag === data)
      if (i > -1) {
        notifications.splice(i, 1)
      }
    })

    socket.on('verifySvgInjectionChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placecats.com\/(g\/)?[\d]+\/[\d]+.*/) && security.isRedirectAllowed(data) })
    })

    socket.on('verifyCloseNotificationsChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
    })
  })
}

export default registerWebsocketEvents
