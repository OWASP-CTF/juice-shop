/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'
import { MatIconModule } from '@angular/material/icon'
import { MatCheckboxModule } from '@angular/material/checkbox'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'
import { MatInputModule } from '@angular/material/input'

import { provideHttpClientTesting } from '@angular/common/http/testing'
import { RouterTestingModule } from '@angular/router/testing'

import { OAuthComponent } from './oauth.component'
import { LoginComponent } from '../login/login.component'
import { ReactiveFormsModule } from '@angular/forms'
import { ActivatedRoute } from '@angular/router'
import { MatTooltipModule } from '@angular/material/tooltip'
import { of, throwError } from 'rxjs'
import { UserService } from '../Services/user.service'
import { CookieModule } from 'ngy-cookie'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

/* Password the component derives for the OAuth provider account id '1234567890'. */
const DERIVED_PASSWORD = 'anVpY2Utc2hvcC1vYXV0aC12MiUzQTEyMzQ1Njc4OTAlM0F0ZXN0JTQwdGVzdC5jb20='
/* base64 of the reversed address - what the component used to use, and what any attacker
   knowing the address could compute. No code path may produce this value again. */
const EMAIL_DERIVED_PASSWORD = 'bW9jLnRzZXRAdHNldA=='

describe('OAuthComponent', () => {
    let component: OAuthComponent
    let fixture: ComponentFixture<OAuthComponent>
    let userService: any

    beforeEach(async () => {
        userService = {
            oauthLogin: vi.fn().mockName("UserService.oauthLogin"),
            login: vi.fn().mockName("UserService.login"),
            save: vi.fn().mockName("UserService.save")
        }
        userService.oauthLogin.mockReturnValue(of({ email: '' }))
        userService.login.mockReturnValue(of({}))
        userService.save.mockReturnValue(of({}))
        userService.isLoggedIn = {
            next: vi.fn().mockName("userService.isLoggedIn.next")
        }
        userService.isLoggedIn.next.mockReturnValue({})

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: 'login', component: LoginComponent }
                ]),
                ReactiveFormsModule,
                CookieModule.forRoot(),
                TranslateModule.forRoot(),
                MatInputModule,
                MatIconModule,
                MatCardModule,
                MatFormFieldModule,
                MatCheckboxModule,
                MatTooltipModule,
                OAuthComponent, LoginComponent],
            providers: [
                { provide: ActivatedRoute, useValue: { snapshot: { data: { params: '?alt=json&access_token=TEST' } } } },
                { provide: UserService, useValue: userService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(OAuthComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('removes authentication token and basket id on failed OAuth login attempt', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        userService.oauthLogin.mockReturnValue(throwError({ error: 'Error' }))
        component.ngOnInit()
        expect(localStorage.getItem('token')).toBeNull()
        expect(sessionStorage.getItem('bid')).toBeNull()
    })

    it('will create regular user account with a password bound to the OAuth provider account id', () => {
        userService.oauthLogin.mockReturnValue(of({ id: '1234567890', email: 'test@test.com' }))
        component.ngOnInit()
        expect(userService.save).toHaveBeenCalledWith({ email: 'test@test.com', password: DERIVED_PASSWORD, passwordRepeat: DERIVED_PASSWORD })
    })

    it('never derives the account password from the email address alone', () => {
        userService.oauthLogin.mockReturnValue(of({ id: '1234567890', email: 'test@test.com' }))
        userService.save.mockClear()
        component.ngOnInit()
        const savedPassword = userService.save.mock.calls[0][0].password
        expect(savedPassword).not.toBe(EMAIL_DERIVED_PASSWORD)
        expect(userService.login).toHaveBeenCalledWith({ email: 'test@test.com', password: savedPassword, oauth: true })
    })

    it('falls back to an unpredictable password when the provider returns no account id', () => {
        userService.oauthLogin.mockReturnValue(of({ email: 'test@test.com' }))
        userService.save.mockClear()
        component.ngOnInit()
        component.ngOnInit()
        const firstPassword = userService.save.mock.calls[0][0].password
        const secondPassword = userService.save.mock.calls[1][0].password
        expect(firstPassword).not.toBe(EMAIL_DERIVED_PASSWORD)
        expect(firstPassword).not.toBe(secondPassword)
        expect(userService.login).toHaveBeenCalledWith({ email: 'test@test.com', password: firstPassword, oauth: true })
    })

    it('logs in user even after failed account creation as account might already have existed from previous OAuth login', () => {
        userService.oauthLogin.mockReturnValue(of({ id: '1234567890', email: 'test@test.com' }))
        userService.save.mockReturnValue(throwError({ error: 'Account already exists' }))
        component.ngOnInit()
        expect(userService.login).toHaveBeenCalledWith({ email: 'test@test.com', password: DERIVED_PASSWORD, oauth: true })
    })

    it('removes authentication token and basket id on failed subsequent regular login attempt', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        userService.login.mockReturnValue(throwError({ error: 'Error' }))
        component.login({ email: '' })
        expect(localStorage.getItem('token')).toBeNull()
        expect(sessionStorage.getItem('bid')).toBeNull()
    })
})
