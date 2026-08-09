/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type CanActivate, Router } from '@angular/router'
import { jwtDecode } from 'jwt-decode'
import { roles } from './roles'
import { Injectable, NgZone, inject } from '@angular/core'
import { type Observable, of } from 'rxjs'
import { catchError, map, tap } from 'rxjs/operators'
import { UserService } from './Services/user.service'

/**
 * Determines the role of the current session on the server instead of reading it from the
 * JWT that happens to sit in the browser storage. That token is fully under the control of
 * the client and can be replaced by a self-crafted one, so it must never be the basis of an
 * access decision. Any problem while asking the server (including an unreachable backend)
 * resolves to "no role at all" so that the guards using this helper fail closed.
 */
function serverSideRole (userService: UserService): Observable<string | undefined> {
  return userService.whoAmI(['role']).pipe(
    map((user: any) => user?.role as string | undefined),
    catchError(() => of(undefined))
  )
}

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

@Injectable()
export class AdminGuard implements CanActivate {
  private readonly loginGuard = inject(LoginGuard)
  private readonly userService = inject(UserService)


  canActivate (): Observable<boolean> {
    return serverSideRole(this.userService).pipe(
      map((role) => role === roles.admin),
      tap((isAuthorized) => {
        if (!isAuthorized) {
          this.loginGuard.forbidRoute()
        }
      })
    )
  }
}

@Injectable()
export class AccountingGuard implements CanActivate {
  private readonly loginGuard = inject(LoginGuard)
  private readonly userService = inject(UserService)


  canActivate (): Observable<boolean> {
    return serverSideRole(this.userService).pipe(
      map((role) => role === roles.accounting),
      tap((isAuthorized) => {
        if (!isAuthorized) {
          this.loginGuard.forbidRoute()
        }
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
