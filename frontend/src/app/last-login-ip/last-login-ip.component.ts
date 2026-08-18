/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, OnInit } from '@angular/core'
import { jwtDecode } from 'jwt-decode'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

@Component({
  selector: 'app-last-login-ip',
  templateUrl: './last-login-ip.component.html',
  styleUrls: ['./last-login-ip.component.scss'],
  imports: [MatCardModule, TranslateModule]
})

export class LastLoginIpComponent implements OnInit {
  /* The address shown here comes from a request header the visitor writes themselves, so it is a
     string of unknown provenance and nothing more. It used to be pasted into a fragment of markup
     that was then handed to the sanitiser bypass, which tells Angular to trust the result and
     insert it as HTML - the one thing that turns an attacker-authored string into an attacker-
     authored element. There is nothing to mark up: the wrapper is part of the template, and the
     value is bound as text so the framework escapes it like any other piece of data. */
  lastLoginIp = '?'

  ngOnInit (): void {
    try {
      this.parseAuthToken()
    } catch (err) {
      console.log(err)
    }
  }

  parseAuthToken () {
    let payload = {} as any
    const token = localStorage.getItem('token')
    if (token) {
      payload = jwtDecode(token)
      if (payload.data.lastLoginIp) {
        this.lastLoginIp = String(payload.data.lastLoginIp)
      }
    }
  }
}
