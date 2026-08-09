/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { HttpClient } from '@angular/common/http'
import { Injectable, inject } from '@angular/core'
import { catchError, map } from 'rxjs/operators'

@Injectable({
  providedIn: 'root'
})
export class SecurityAnswerService {
  private readonly http = inject(HttpClient)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/api/SecurityAnswers'

  /* The token is passed explicitly for the registration flow, which has to authenticate
     as the brand new account without starting a session for it. */
  save (params: any, token?: string) {
    const options = token ? { headers: { Authorization: `Bearer ${token}` } } : {}
    return this.http.post(this.host + '/', params, options).pipe(
      map((response: any) => response.data),
      catchError((err) => { throw err })
    )
  }
}
