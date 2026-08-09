/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type CanActivate, Router } from '@angular/router'
import { jwtDecode } from 'jwt-decode'
import { roles } from './roles'
import { Injectable, NgZone, inject } from '@angular/core'
import { UserService } from './Services/user.service'
import { type Observable, of } from 'rxjs'
import { catchError, map } from 'rxjs/operators'

@Injectable()
export class LoginGuard implements CanActivate {
  private readonly router = inject(Router)
  private readonly ngZone = inject(NgZone)


  canActivate () {
    if (localStorage.getItem('token')) {
      return true
    } else {
      this.forbidRoute('UNAUTHORIZED_ACCESS_ERROR')
      return false
    }
  }

  forbidRoute (error = 'UNAUTHORIZED_PAGE_ACCESS_ERROR') {
    this.ngZone.run(async () => await this.router.navigate(['403'], {
      skipLocationChange: true,
      queryParams: { error }
    }))
  }

  tokenDecode () {
    let payload: any = null
    const token = localStorage.getItem('token')
    if (token) {
      try {
        payload = jwtDecode(token)
      } catch (err) {
        console.log(err)
      }
    }
    return payload
  }
}

// The role is asked of the server rather than read out of the token in local storage.
// jwtDecode only base64-decodes the payload - it verifies no signature - so a user could
// rewrite their own token to claim the admin role and walk straight into these routes.
// /rest/user/whoami answers from the server-side session for a token the server has
// verified, so the client cannot author the answer. A failed lookup denies.
@Injectable()
export class AdminGuard implements CanActivate {
  private readonly loginGuard = inject(LoginGuard)
  private readonly userService = inject(UserService)

  canActivate (): Observable<boolean> {
    return this.userService.whoAmI().pipe(
      map((user: any) => {
        if (user?.role === roles.admin) {
          return true
        }
        this.loginGuard.forbidRoute()
        return false
      }),
      catchError(() => {
        this.loginGuard.forbidRoute()
        return of(false)
      })
    )
  }
}

@Injectable()
export class AccountingGuard implements CanActivate {
  private readonly loginGuard = inject(LoginGuard)
  private readonly userService = inject(UserService)

  canActivate (): Observable<boolean> {
    return this.userService.whoAmI().pipe(
      map((user: any) => {
        if (user?.role === roles.accounting) {
          return true
        }
        this.loginGuard.forbidRoute()
        return false
      }),
      catchError(() => {
        this.loginGuard.forbidRoute()
        return of(false)
      })
    )
  }
}

@Injectable()
export class DeluxeGuard {
  private readonly loginGuard = inject(LoginGuard)


  isDeluxe () {
    const payload = this.loginGuard.tokenDecode()
    return payload?.data && payload.data.role === roles.deluxe
  }
}
