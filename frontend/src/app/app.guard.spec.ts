/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { AccountingGuard, AdminGuard, DeluxeGuard, LoginGuard } from './app.guard'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { RouterTestingModule } from '@angular/router/testing'
import { ErrorPageComponent } from './error-page/error-page.component'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { UserService } from './Services/user.service'
import { of, throwError } from 'rxjs'

describe('LoginGuard', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [LoginGuard, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('should be created', () => {
        const guard = TestBed.inject(LoginGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for authenticated users', () => {
        const guard = TestBed.inject(LoginGuard)

        localStorage.setItem('token', 'TOKEN')
        expect(guard.canActivate()).toBe(true)
    })

    it('should close for anonymous users', () => {
        const guard = TestBed.inject(LoginGuard)

        localStorage.removeItem('token')
        expect(guard.canActivate()).toBe(false)
    })

    it('returns payload from decoding a valid JWT', () => {
        const guard = TestBed.inject(LoginGuard)

        localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
        expect(guard.tokenDecode()).toEqual({
            sub: '1234567890',
            name: 'John Doe',
            iat: 1516239022
        })
    })

    it('returns nothing when decoding an invalid JWT', () => {
        const guard = TestBed.inject(LoginGuard)

        localStorage.setItem('token', '12345.abcde')
        expect(guard.tokenDecode()).toBeNull()
    })

    it('returns nothing when decoding an non-existing JWT', () => {
        const guard = TestBed.inject(LoginGuard)

        localStorage.removeItem('token')
        expect(guard.tokenDecode()).toBeNull()
    })
})

describe('AdminGuard', () => {
    let loginGuard: any
    let userService: any

    beforeEach(() => {
        loginGuard = {
            tokenDecode: vi.fn().mockName("LoginGuard.tokenDecode"),
            forbidRoute: vi.fn().mockName("LoginGuard.forbidRoute")
        }
        // The guard asks the server for the role now, so the role under test is the one
        // /rest/user/whoami reports - not one decoded from a token the client could edit.
        userService = { whoAmI: vi.fn().mockName("UserService.whoAmI") }

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [
                AdminGuard,
                { provide: LoginGuard, useValue: loginGuard },
                { provide: UserService, useValue: userService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
    })

    const activate = (guard: any) => {
        let result: boolean | undefined
        guard.canActivate().subscribe((allowed: boolean) => { result = allowed })
        return result
    }

    it('should be created', () => {
        const guard = TestBed.inject(AdminGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for admins', () => {
        const guard = TestBed.inject(AdminGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'admin' }))
        expect(activate(guard)).toBe(true)
    })

    it('should close for regular customers', () => {
        const guard = TestBed.inject(AdminGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'customer' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for deluxe customers', () => {
        const guard = TestBed.inject(AdminGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'deluxe' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for accountants', () => {
        const guard = TestBed.inject(AdminGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'accounting' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close when a forged token claims the admin role', () => {
        const guard = TestBed.inject(AdminGuard)

        // The client-side token says admin; the server says customer. The server wins.
        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'admin' } })
        userService.whoAmI.mockReturnValue(of({ role: 'customer' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close when the role lookup fails', () => {
        const guard = TestBed.inject(AdminGuard)

        userService.whoAmI.mockReturnValue(throwError(() => new Error('network down')))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })
})

describe('AccountingGuard', () => {
    let loginGuard: any
    let userService: any

    beforeEach(() => {
        loginGuard = {
            tokenDecode: vi.fn().mockName("LoginGuard.tokenDecode"),
            forbidRoute: vi.fn().mockName("LoginGuard.forbidRoute")
        }
        userService = { whoAmI: vi.fn().mockName("UserService.whoAmI") }

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [
                AccountingGuard,
                { provide: LoginGuard, useValue: loginGuard },
                { provide: UserService, useValue: userService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
    })

    const activate = (guard: any) => {
        let result: boolean | undefined
        guard.canActivate().subscribe((allowed: boolean) => { result = allowed })
        return result
    }

    it('should be created', () => {
        const guard = TestBed.inject(AccountingGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for accountants', () => {
        const guard = TestBed.inject(AccountingGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'accounting' }))
        expect(activate(guard)).toBe(true)
    })

    it('should close for regular customers', () => {
        const guard = TestBed.inject(AccountingGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'customer' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for deluxe customers', () => {
        const guard = TestBed.inject(AccountingGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'deluxe' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for admins', () => {
        const guard = TestBed.inject(AccountingGuard)

        userService.whoAmI.mockReturnValue(of({ role: 'admin' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close when a forged token claims the accounting role', () => {
        const guard = TestBed.inject(AccountingGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'accounting' } })
        userService.whoAmI.mockReturnValue(of({ role: 'customer' }))
        expect(activate(guard)).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })
})

describe('DeluxeGuard', () => {
    let loginGuard: any

    beforeEach(() => {
        loginGuard = {
            tokenDecode: vi.fn().mockName("LoginGuard.tokenDecode")
        }

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [
                DeluxeGuard,
                { provide: LoginGuard, useValue: loginGuard },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
    })

    it('should be created', () => {
        const guard = TestBed.inject(DeluxeGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for deluxe customers', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'deluxe' } })
        expect(guard.isDeluxe()).toBe(true)
    })

    it('should close for regular customers', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'customer' } })
        expect(guard.isDeluxe()).toBe(false)
    })

    it('should close for admins', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'admin' } })
        expect(guard.isDeluxe()).toBe(false)
    })

    it('should close for accountants', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'accounting' } })
        expect(guard.isDeluxe()).toBe(false)
    })
})
