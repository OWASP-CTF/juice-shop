/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

/* The shop's own client only ever renders a small, well-known part of the server's
   configuration. Everything else in it is operational data: the seeded account-recovery
   answers under `memories`, the product bookkeeping that drives several internal
   behaviours, the chat bot's LLM endpoint, the listening port, the mail domain used to
   pre-load accounts. None of that belongs in a response to an anonymous shop visitor,
   so the public answer is assembled from an explicit allowlist rather than by handing
   out the whole configuration object and deleting a field or two from it. */
function publicConfiguration (configuration: any) {
  const application = configuration?.application ?? {}
  const challenges = configuration?.challenges ?? {}
  const hackingInstructor = configuration?.hackingInstructor ?? {}
  const ctf = configuration?.ctf ?? {}
  return {
    application: {
      name: application.name,
      logo: application.logo,
      favicon: application.favicon,
      theme: application.theme,
      showVersionNumber: application.showVersionNumber,
      showGitHubLinks: application.showGitHubLinks,
      altcoinName: application.altcoinName,
      privacyContactEmail: application.privacyContactEmail,
      social: application.social,
      recyclePage: application.recyclePage,
      welcomeBanner: application.welcomeBanner,
      cookieConsent: application.cookieConsent,
      promotion: application.promotion,
      easterEggPlanet: application.easterEggPlanet,
      googleOauth: application.googleOauth,
      chatBot: {
        name: application.chatBot?.name,
        avatar: application.chatBot?.avatar,
        sampleQuestions: application.chatBot?.sampleQuestions
      }
    },
    challenges: {
      showSolvedNotifications: challenges.showSolvedNotifications,
      showHints: challenges.showHints,
      showMitigations: challenges.showMitigations,
      codingChallengesEnabled: challenges.codingChallengesEnabled,
      restrictToTutorialsFirst: challenges.restrictToTutorialsFirst,
      safetyMode: challenges.safetyMode
    },
    hackingInstructor: {
      isEnabled: hackingInstructor.isEnabled,
      avatarImage: hackingInstructor.avatarImage,
      hintPlaybackSpeed: hackingInstructor.hintPlaybackSpeed
    },
    ctf: {
      showFlagsInNotifications: ctf.showFlagsInNotifications,
      showCountryDetailsInNotifications: ctf.showCountryDetailsInNotifications,
      systemWideNotifications: ctf.systemWideNotifications
    }
  }
}

/* Administrators legitimately need to inspect how the running instance is configured.
   Secrets stay out of that answer as well: an API endpoint of the LLM backend and the
   seeded answers to the account-recovery questions are credentials, and there is no
   role that needs to read them back over HTTP. */
function administrativeConfiguration (configuration: any) {
  const adminConfig = structuredClone(configuration)
  if (adminConfig?.application?.chatBot) {
    delete adminConfig.application.chatBot.llmApiUrl
  }
  if (Array.isArray(adminConfig?.memories)) {
    for (const memory of adminConfig.memories) {
      delete memory.geoStalkingMetaSecurityAnswer
      delete memory.geoStalkingVisualSecurityAnswer
    }
  }
  return adminConfig
}

function isAdmin (req: Request) {
  const token = utils.jwtFrom(req)
  if (!token || !security.verify(token)) {
    return false
  }
  const decodedToken: any = security.decode(token)
  return decodedToken?.data?.role === security.roles.admin
}

export function retrieveAppConfiguration () {
  return (req: Request, res: Response) => {
    const configuration = config.util.toObject(config)
    res.json({ config: isAdmin(req) ? administrativeConfiguration(configuration) : publicConfiguration(configuration) })
  }
}
