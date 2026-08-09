/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { UserService } from '../Services/user.service'
import { SecurityQuestionService } from '../Services/security-question.service'
import { type AbstractControl, UntypedFormControl, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms'
import { Component, inject } from '@angular/core'
import { library } from '@fortawesome/fontawesome-svg-core'
import { faSave } from '@fortawesome/free-solid-svg-icons'
import { faEdit } from '@fortawesome/free-regular-svg-icons'
import { type SecurityQuestion } from '../Models/securityQuestion.model'
import { TranslateService, TranslateModule } from '@ngx-translate/core'
import { MatButtonModule } from '@angular/material/button'
import { PasswordStrengthComponent } from '../password-strength/password-strength.component'
import { PasswordStrengthInfoComponent } from '../password-strength-info/password-strength-info.component'
import { MatSlideToggle } from '@angular/material/slide-toggle'

import { MatTooltip } from '@angular/material/tooltip'
import { MatIconModule } from '@angular/material/icon'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule, MatLabel, MatSuffix, MatError, MatHint } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'

library.add(faSave, faEdit)

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.scss'],
  imports: [MatCardModule, TranslateModule, MatFormFieldModule, MatLabel, MatInputModule, FormsModule, ReactiveFormsModule, MatIconModule, MatSuffix, MatTooltip, MatError, MatHint, MatSlideToggle, PasswordStrengthComponent, PasswordStrengthInfoComponent, MatButtonModule]
})
export class ForgotPasswordComponent {
  private readonly securityQuestionService = inject(SecurityQuestionService)
  private readonly userService = inject(UserService)
  private readonly translate = inject(TranslateService)

  public emailControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, Validators.email])
  public securityQuestionControl: UntypedFormControl = new UntypedFormControl({ disabled: true, value: '' }, [Validators.required])
  public passwordControl: UntypedFormControl = new UntypedFormControl({ disabled: true, value: '' }, [Validators.required, Validators.minLength(5)])
  public repeatPasswordControl: UntypedFormControl = new UntypedFormControl({ disabled: true, value: '' }, [Validators.required, matchValidator(this.passwordControl)])
  /* Second factor: the one-time token from the reset link. Only asked for once the
     security answer has been accepted, since the answer alone no longer resets anything. */
  public tokenControl: UntypedFormControl = new UntypedFormControl({ disabled: true, value: '' })
  public awaitingToken = false
  public securityQuestion?: string
  public error?: string
  public confirmation?: string
  public timeoutDuration = 1000
  private timeout

  findSecurityQuestion () {
    clearTimeout(this.timeout)
    this.timeout = setTimeout(() => {
      this.securityQuestion = undefined
      if (this.emailControl.value) {
        this.securityQuestionService.findBy(this.emailControl.value).subscribe({
          next: (securityQuestion: SecurityQuestion) => {
            if (securityQuestion) {
              this.securityQuestion = securityQuestion.question
              this.securityQuestionControl.enable()
              this.passwordControl.enable()
              this.repeatPasswordControl.enable()
            } else {
              this.securityQuestionControl.disable()
              this.passwordControl.disable()
              this.repeatPasswordControl.disable()
            }
          },
          error: (error) => error
        }
        )
      } else {
        this.securityQuestionControl.disable()
        this.passwordControl.disable()
        this.repeatPasswordControl.disable()
      }
    }, this.timeoutDuration)
  }

  resetPassword () {
    const token = this.tokenControl.value
    this.userService.resetPassword({
      email: this.emailControl.value,
      answer: this.securityQuestionControl.value,
      new: this.passwordControl.value,
      repeat: this.repeatPasswordControl.value,
      ...(token ? { token } : {})
    }).subscribe({
      next: () => {
        this.error = undefined
        if (!token) {
          /* The answer was right, but it only requested the reset. Keep the form
             filled and ask for the one-time token that was sent out of band. */
          this.awaitingToken = true
          this.tokenControl.enable()
          this.showConfirmation('PASSWORD_RESET_LINK_SENT')
          return
        }
        this.showConfirmation('PASSWORD_SUCCESSFULLY_CHANGED')
        this.awaitingToken = false
        this.resetForm()
      },
      error: (error) => {
        this.error = error.error
        this.confirmation = undefined
        this.resetErrorForm()
      }
    })
  }

  private showConfirmation (translationKey: string) {
    this.translate.get(translationKey).subscribe({
      next: (translated) => {
        this.confirmation = translated
      },
      error: (translationId) => {
        this.confirmation = translationId
      }
    })
  }

  resetForm () {
    this.emailControl.setValue('')
    this.emailControl.markAsPristine()
    this.emailControl.markAsUntouched()
    this.securityQuestionControl.setValue('')
    this.securityQuestionControl.markAsPristine()
    this.securityQuestionControl.markAsUntouched()
    this.passwordControl.setValue('')
    this.passwordControl.markAsPristine()
    this.passwordControl.markAsUntouched()
    this.repeatPasswordControl.setValue('')
    this.repeatPasswordControl.markAsPristine()
    this.repeatPasswordControl.markAsUntouched()
    this.clearToken()
  }

  private clearToken () {
    this.tokenControl.setValue('')
    this.tokenControl.markAsPristine()
    this.tokenControl.markAsUntouched()
    this.tokenControl.disable()
  }

  resetErrorForm () {
    this.emailControl.markAsPristine()
    this.emailControl.markAsUntouched()
    this.securityQuestionControl.setValue('')
    this.securityQuestionControl.markAsPristine()
    this.securityQuestionControl.markAsUntouched()
    this.passwordControl.setValue('')
    this.passwordControl.markAsPristine()
    this.passwordControl.markAsUntouched()
    this.repeatPasswordControl.setValue('')
    this.repeatPasswordControl.markAsPristine()
    this.repeatPasswordControl.markAsUntouched()
    /* A rejected or expired token sends the user back to requesting a fresh one. */
    this.awaitingToken = false
    this.clearToken()
  }
}

function matchValidator (passwordControl: AbstractControl) {
  return function matchOtherValidate (repeatPasswordControl: UntypedFormControl) {
    const password = passwordControl.value
    const passwordRepeat = repeatPasswordControl.value
    if (password !== passwordRepeat) {
      return { notSame: true }
    }
    return null
  }
}
