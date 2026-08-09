/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* eslint-disable @typescript-eslint/no-unused-vars */
import { TokenSaleComponent } from './token-sale/token-sale.component'
import { OAuthComponent } from './oauth/oauth.component'
import { BasketComponent } from './basket/basket.component'
import { TrackResultComponent } from './track-result/track-result.component'
import { ContactComponent } from './contact/contact.component'
import { RegisterComponent } from './register/register.component'
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component'
import { SearchResultComponent } from './search-result/search-result.component'
import { LoginComponent } from './login/login.component'
import { AdministrationComponent } from './administration/administration.component'
import { ChangePasswordComponent } from './change-password/change-password.component'
import { ComplaintComponent } from './complaint/complaint.component'
import { RouterModule, type Routes, type UrlMatchResult, type UrlSegment } from '@angular/router'
import { TwoFactorAuthEnterComponent } from './two-factor-auth-enter/two-factor-auth-enter.component'
import { ErrorPageComponent } from './error-page/error-page.component'
import { PrivacySecurityComponent } from './privacy-security/privacy-security.component'
import { TwoFactorAuthComponent } from './two-factor-auth/two-factor-auth.component'
import { DataExportComponent } from './data-export/data-export.component'
import { LastLoginIpComponent } from './last-login-ip/last-login-ip.component'
import { PrivacyPolicyComponent } from './privacy-policy/privacy-policy.component'
import { AddressCreateComponent } from './address-create/address-create.component'
import { AddressSelectComponent } from './address-select/address-select.component'
import { SavedAddressComponent } from './saved-address/saved-address.component'
import { PaymentComponent } from './payment/payment.component'
import { SavedPaymentMethodsComponent } from './saved-payment-methods/saved-payment-methods.component'
import { AccountingComponent } from './accounting/accounting.component'
import { OrderCompletionComponent } from './order-completion/order-completion.component'
import { OrderSummaryComponent } from './order-summary/order-summary.component'
import { WalletComponent } from './wallet/wallet.component'
import { OrderHistoryComponent } from './order-history/order-history.component'
import { DeliveryMethodComponent } from './delivery-method/delivery-method.component'
import { PhotoWallComponent } from './photo-wall/photo-wall.component'
import { DeluxeUserComponent } from './deluxe-user/deluxe-user.component'
import { AccountingGuard, AdminGuard, LoginGuard } from './app.guard'
import { NFTUnlockComponent } from './nft-unlock/nft-unlock.component'
import { ScoreBoardComponent } from './score-board/score-board.component'
import { ChatbotComponent } from './chatbot/chatbot.component'
import { ChatWelcomePageComponent } from './chatbot/chat-welcome-page/chat-welcome-page.component'
import { ChatConversationComponent } from './chatbot/chat-conversation/chat-conversation.component'

const loadFaucetModule = async () => {
  const module = await import('./faucet/faucet.module')
  return module.FaucetModule
}
const loadWeb3WalletModule = async () => {
  const module = await import('./wallet-web3/wallet-web3.module')
  return module.WalletWeb3Module
}

const loadCodingChallenge = async () => {
  const module = await import('./coding-challenge-page/coding-challenge-page.component')
  return module.CodingChallengePageComponent
}

const loadRecycleComponent = async () => {
  const module = await import('./recycle/recycle.component')
  return module.RecycleComponent
}

const loadAboutComponent = async () => {
  const module = await import('./about/about.component')
  return module.AboutComponent
}

// vuln-code-snippet start adminSectionChallenge scoreBoardChallenge web3SandboxChallenge
const routes: Routes = [
  { // vuln-code-snippet neutral-line adminSectionChallenge
    path: 'administration', // vuln-code-snippet vuln-line adminSectionChallenge
    component: AdministrationComponent, // vuln-code-snippet neutral-line adminSectionChallenge
    canActivate: [AdminGuard] // vuln-code-snippet neutral-line adminSectionChallenge
  }, // vuln-code-snippet neutral-line adminSectionChallenge
  {
    path: 'accounting',
    component: AccountingComponent,
    canActivate: [AccountingGuard]
  },
  {
    path: 'about',
    loadComponent: async () => await loadAboutComponent()
  },
  {
    path: 'address/select',
    component: AddressSelectComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'address/saved',
    component: SavedAddressComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'address/create',
    component: AddressCreateComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'address/edit/:addressId',
    component: AddressCreateComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'delivery-method',
    component: DeliveryMethodComponent
  },
  {
    path: 'deluxe-membership',
    component: DeluxeUserComponent,
    canActivate: [LoginGuard]
  },
  {
    path: 'saved-payment-methods',
    component: SavedPaymentMethodsComponent
  },
  {
    path: 'basket',
    component: BasketComponent
  },
  {
    path: 'order-completion/:id',
    component: OrderCompletionComponent
  },
  {
    path: 'contact',
    component: ContactComponent
  },
  {
    path: 'photo-wall',
    component: PhotoWallComponent
  },
  {
    path: 'complain',
    component: ComplaintComponent
  },
  {
    path: 'order-summary',
    component: OrderSummaryComponent
  },
  {
    path: 'order-history',
    component: OrderHistoryComponent
  },
  {
    path: 'payment/:entity',
    component: PaymentComponent
  },
  {
    path: 'wallet',
    component: WalletComponent
  },
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'forgot-password',
    component: ForgotPasswordComponent
  },
  {
    path: 'recycle',
    loadComponent: async () => await loadRecycleComponent()
  },
  {
    path: 'register',
    component: RegisterComponent
  },
  {
    path: 'search',
    component: SearchResultComponent
  },
  {
    path: 'hacking-instructor',
    component: SearchResultComponent
  },
  { // vuln-code-snippet neutral-line scoreBoardChallenge
    path: 'score-board', // vuln-code-snippet vuln-line scoreBoardChallenge
    component: ScoreBoardComponent // vuln-code-snippet neutral-line scoreBoardChallenge
  }, // vuln-code-snippet neutral-line scoreBoardChallenge
  {
    path: 'track-result',
    component: TrackResultComponent
  },
  {
    path: 'track-result/new',
    component: TrackResultComponent,
    data: {
      type: 'new'
    }
  },
  {
    path: '2fa/enter',
    component: TwoFactorAuthEnterComponent
  },
  {
    path: 'privacy-security',
    component: PrivacySecurityComponent,
    children: [
      {
        path: 'privacy-policy',
        component: PrivacyPolicyComponent
      },
      {
        path: 'change-password',
        component: ChangePasswordComponent
      },
      {
        path: 'two-factor-authentication',
        component: TwoFactorAuthComponent
      },
      {
        path: 'data-export',
        component: DataExportComponent
      },
      {
        path: 'last-login-ip',
        component: LastLoginIpComponent
      }
    ]
  },
  {
    path: 'juicy-nft',
    component: NFTUnlockComponent
  },
  {
    path: 'wallet-web3',
    loadChildren: async () => await loadWeb3WalletModule()
  },
  /* An on-the-fly editor that compiles and deploys smart contracts was a prototyping aid for the
     developers and was never meant to leave their machines. Nothing in the shop linked to it, so
     the only thing standing between a visitor and it was not knowing the path - and the routing
     table is part of the bundle every visitor downloads, so the path was never actually secret.
     A guard would leave a tool that has no business being on a shop's origin one credential away
     from the public, so the route is withdrawn rather than restricted. */
  {
    path: 'chatbot',
    component: ChatbotComponent,
    children: [
      { path: '', component: ChatWelcomePageComponent },
      { path: 'conversation/:id', component: ChatConversationComponent }
    ]
  },
  {
    path: 'bee-haven',
    loadChildren: async () => await loadFaucetModule()
  },
  // vuln-code-snippet start tokenSaleChallenge
  {
    matcher: oauthMatcher,
    data: { params: (window.location.href).substr(window.location.href.indexOf('#')) },
    component: OAuthComponent
  },
  /* The token sale page describes an offering that has not been announced yet, so it is internal
     material until it is not. What used to stand between a visitor and that page was nothing but a
     hard-to-read address: the route matched a string that was assembled at runtime out of
     arithmetic instead of being written down. That is not a permission check. The routing table is
     part of the bundle every browser downloads, so the address can be recovered by anyone who
     cares to run the same arithmetic, and once recovered it opens the page for everybody - there is
     no notion of who is allowed in. The route is spelled out plainly now and admission is decided
     by the same role check that guards the shop's other internal areas, so the page is withheld
     from visitors who were never granted access rather than merely hidden from them. */
  { // vuln-code-snippet neutral-line tokenSaleChallenge
    path: 'tokensale-ico-ea', // vuln-code-snippet vuln-line tokenSaleChallenge
    component: TokenSaleComponent, // vuln-code-snippet neutral-line tokenSaleChallenge
    canActivate: [AdminGuard] // vuln-code-snippet neutral-line tokenSaleChallenge
  }, // vuln-code-snippet neutral-line tokenSaleChallenge
  {
    path: 'coding-challenge/:challengeKey',
    loadComponent: async () => await loadCodingChallenge()
  },
  {
    path: '403',
    component: ErrorPageComponent
  },
  {
    path: '**',
    component: SearchResultComponent
  }
]
// vuln-code-snippet end adminSectionChallenge scoreBoardChallenge web3SandboxChallenge

export const Routing = RouterModule.forRoot(routes, { useHash: true })

export function oauthMatcher (url: UrlSegment[]): UrlMatchResult {
  if (url.length === 0) {
    return null as unknown as UrlMatchResult
  }
  const path = window.location.href
  if (path.includes('#access_token=')) {
    return ({ consumed: url })
  }

  return null as unknown as UrlMatchResult
}

// vuln-code-snippet end tokenSaleChallenge
