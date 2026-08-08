/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const source = config.util.toObject(config) as any
    const application = source.application ?? {}
    const safeConfig = {
      server: {
        port: source.server?.port,
        basePath: source.server?.basePath
      },
      application: {
        domain: application.domain,
        name: application.name,
        logo: application.logo,
        favicon: application.favicon,
        theme: application.theme,
        showVersionNumber: application.showVersionNumber,
        showGitHubLinks: application.showGitHubLinks,
        localBackupEnabled: application.localBackupEnabled,
        numberOfRandomFakeUsers: application.numberOfRandomFakeUsers,
        altcoinName: application.altcoinName,
        privacyContactEmail: application.privacyContactEmail,
        social: application.social,
        chatBot: {
          name: application.chatBot?.name,
          avatar: application.chatBot?.avatar,
          sampleQuestions: application.chatBot?.sampleQuestions
        },
        recyclePage: application.recyclePage,
        welcomeBanner: application.welcomeBanner,
        cookieConsent: application.cookieConsent,
        securityTxt: {
          contact: application.securityTxt?.contact,
          acknowledgements: application.securityTxt?.acknowledgements,
          hiring: application.securityTxt?.hiring,
          csaf: application.securityTxt?.csaf
        },
        promotion: application.promotion,
        easterEggPlanet: application.easterEggPlanet,
        googleOauth: {
          clientId: application.googleOauth?.clientId,
          authorizedRedirects: application.googleOauth?.authorizedRedirects
        }
      },
      challenges: {
        showSolvedNotifications: source.challenges?.showSolvedNotifications,
        showHints: source.challenges?.showHints,
        showMitigations: source.challenges?.showMitigations,
        codingChallengesEnabled: source.challenges?.codingChallengesEnabled,
        restrictToTutorialsFirst: source.challenges?.restrictToTutorialsFirst,
        safetyMode: source.challenges?.safetyMode,
        overwriteUrlForProductTamperingChallenge: source.challenges?.overwriteUrlForProductTamperingChallenge
      },
      hackingInstructor: {
        isEnabled: source.hackingInstructor?.isEnabled,
        avatarImage: source.hackingInstructor?.avatarImage,
        hintPlaybackSpeed: source.hackingInstructor?.hintPlaybackSpeed
      },
      products: (source.products ?? []).map(({ name, price, deluxePrice, limitPerUser, description, image }: any) => ({ name, price, deluxePrice, limitPerUser, description, image })),
      memories: (source.memories ?? []).map(({ image, caption, user }: any) => ({ image, caption, user })),
      ctf: {
        showFlagsInNotifications: source.ctf?.showFlagsInNotifications,
        showCountryDetailsInNotifications: source.ctf?.showCountryDetailsInNotifications,
        countryMapping: source.ctf?.countryMapping,
        systemWideNotifications: source.ctf?.systemWideNotifications
      }
    }
    res.json({ config: safeConfig })
  }
}
