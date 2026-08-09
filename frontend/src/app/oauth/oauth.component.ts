/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { ActivatedRoute, Router } from '@angular/router'
import { UserService } from '../Services/user.service'
import { CookieService } from 'ngy-cookie'
import { Component, NgZone, type OnInit, inject } from '@angular/core'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

@Component({
  selector: 'app-oauth',
  templateUrl: './oauth.component.html',
  styleUrls: ['./oauth.component.scss'],
  imports: [MatCardModule, TranslateModule]
})
export class OAuthComponent implements OnInit {
  private static readonly oauthPasswordScope = 'juice-shop-oauth-v2'

  private readonly cookieService = inject(CookieService)
  private readonly userService = inject(UserService)
  private readonly router = inject(Router)
  private readonly route = inject(ActivatedRoute)
  private readonly ngZone = inject(NgZone)


  ngOnInit (): void {
    this.userService.oauthLogin(this.parseRedirectUrlParams().access_token).subscribe({
      next: (profile: any) => {
        /* The password of the local account is derived once per flow and handed to the
           subsequent login, so the registration and the login always agree even when the
           derivation had to fall back to a random secret. */
        const password = this.derivePassword(profile)
        this.userService.save({ email: profile.email, password, passwordRepeat: password }).subscribe({
          next: () => {
            this.login(profile, password)
          },
          error: () => { this.login(profile, password) }
        })
      },
      error: (error) => {
        this.invalidateSession(error)
        this.ngZone.run(async () => await this.router.navigate(['/login']))
      }
    })
  }

  login (profile: any, password: string = this.derivePassword(profile)) {
    this.userService.login({ email: profile.email, password, oauth: true }).subscribe({
      next: (authentication) => {
        const expires = new Date()
        expires.setHours(expires.getHours() + 8)
        this.cookieService.put('token', authentication.token, { expires })
        localStorage.setItem('token', authentication.token)
        sessionStorage.setItem('bid', authentication.bid)
        this.userService.isLoggedIn.next(true)
        this.ngZone.run(async () => await this.router.navigate(['/']))
      },
      error: (error) => {
        this.invalidateSession(error)
        this.ngZone.run(async () => await this.router.navigate(['/login']))
      }
    })
  }

  /* The local account password used to be btoa(reverse(email)): a pure function of a
     public identifier, computed in code that ships to every browser, so anyone who knew
     an address could log in as that address through the ordinary login form. The password
     is now bound to the identity provider's subject id for the account, which is only
     available to someone who actually completed the OAuth flow for it. It stays stable
     across logins and browsers, so returning users keep working. */
  derivePassword (profile: any): string {
    const subject = profile?.id ?? profile?.sub ?? profile?.user_id
    if (subject === undefined || subject === null || String(subject).length === 0) {
      /* No stable provider identity to bind to. Never fall back to anything derived from
         the address - a one-off random secret keeps this flow self-consistent instead. */
      return this.randomPassword()
    }
    /* encodeURIComponent keeps the payload inside the Latin-1 range btoa accepts, so an
       internationalised address cannot make the derivation throw. */
    return btoa(encodeURIComponent(`${OAuthComponent.oauthPasswordScope}:${String(subject)}:${String(profile?.email ?? '')}`))
  }

  randomPassword (): string {
    const webCrypto: Crypto | undefined = globalThis.crypto
    if (webCrypto?.getRandomValues) {
      const bytes = new Uint8Array(32)
      webCrypto.getRandomValues(bytes)
      return btoa(Array.from(bytes).map((byte) => String.fromCharCode(byte)).join(''))
    }
    return btoa(`${OAuthComponent.oauthPasswordScope}:${Date.now()}:${Math.random()}:${Math.random()}`)
  }

  invalidateSession (error: Error) {
    console.log(error)
    this.cookieService.remove('token')
    localStorage.removeItem('token')
    sessionStorage.removeItem('bid')
  }

  parseRedirectUrlParams () {
    const hash = this.route.snapshot.data.params.substr(1)
    const splitted = hash.split('&')
    const params: any = {}
    for (const part of splitted) {
      const [key, value] = part.split('=')
      params[key] = value
    }
    return params
  }
}
