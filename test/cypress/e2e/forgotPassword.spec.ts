describe('/#/forgot-password', () => {
  beforeEach(() => {
    cy.get('body').then(($body) => {
      if ($body.find('#logout').length) {
        cy.get('#logout').click()
      }
    })
    cy.visit('/#/forgot-password')
    cy.intercept('GET', '/rest/user/security-question?email=*').as('securityQuestion')
  })

  describe('as Jim', () => {
    it('should be able to reset password with his security answer', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`jim@${appDomain}`)
        }
      )
      cy.wait('@securityQuestion')
      cy.get('#securityAnswer').should('not.be.disabled').focus().type('Wq4t-Bn7v-Xj2c-Rm8h')
      // recordings to properly fix behavior during test
      cy.get('#newPassword').focus().type('I <3 Spock')
      cy.get('#newPasswordRepeat').focus().type('I <3 Spock')
      cy.get('#resetButton').click()

      cy.get('.confirmation').should('not.be.hidden')
      cy.expectChallengeSolved({ challenge: "Reset Jim's Password" })
    })
  })

  describe('as Bender', () => {
    it('should be able to reset password with his security answer', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`bender@${appDomain}`)
        }
      )
      cy.wait('@securityQuestion')
      cy.get('#securityAnswer').should('not.be.disabled').focus().type('Vd6k-Ptm3-Ghs9-Ynb4')
      // recordings to properly fix behavior during test
      cy.get('#newPassword').focus().type('Brannigan 8=o Leela')
      cy.get('#newPasswordRepeat').focus().type('Brannigan 8=o Leela')
      cy.get('#resetButton').click()

      cy.get('.confirmation').should('not.be.hidden')
      cy.expectChallengeSolved({ challenge: "Reset Bender's Password" })
    })
  })

  describe('as Bjoern', () => {
    describe('for his internal account', () => {
      it('should be able to reset password with his security answer', () => {
        cy.task<string>('GetFromConfig', 'application.domain').then(
          (appDomain: string) => {
            cy.get('#email').type(`bjoern@${appDomain}`)
          }
        )
        cy.wait('@securityQuestion')
        cy.get('#securityAnswer').should('not.be.disabled').focus().type('Ns5b-Kxr9-Dhq4-Wvt6')
        // recordings to properly fix behavior during test
        cy.get('#newPassword').focus().type('monkey birthday ')
        cy.get('#newPasswordRepeat').focus().type('monkey birthday ')
        cy.get('#resetButton').click()

        cy.get('.confirmation').should('not.be.hidden')
        cy.expectChallengeSolved({ challenge: "Reset Bjoern's Password" })
      })
    })

    describe('for his OWASP account', () => {
      // The "Bjoern's Favorite Pet" challenge is patched: this account's security answer is no
      // longer the publicly doxxed real-world pet name, so it can no longer be recovered by
      // OSINT and the challenge is no longer solvable. Only the rotated high-entropy secret
      // resets the password, which this test still covers to prove the flow itself works.
      it('should be able to reset password with his security answer', () => {
        cy.get('#email').type('bjoern@owasp.org')
        cy.wait('@securityQuestion')
        cy.get('#securityAnswer').should('not.be.disabled').focus().type('K8v#pR2mQ!7wZtN4xLd$3bYhF9sJcE6a')
        // recordings to properly fix behavior during test
        cy.get('#newPassword').focus().type('kitten lesser pooch')
        cy.get('#newPasswordRepeat').focus().type('kitten lesser pooch')
        cy.get('#resetButton').click()

        cy.get('.confirmation').should('not.be.hidden')
      })
    })
  })

  describe('as Morty', () => {
    it('should be able to reset password with his security answer', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`morty@${appDomain}`)
        }
      )
      cy.wait('@securityQuestion')
      cy.get('#securityAnswer').should('not.be.disabled').focus().type('Lc8n-Rwq5-Tfd2-Zjm7')
      // recordings to properly fix behavior during test
      cy.get('#newPassword').focus().type('iBurri3dMySe1f!')
      cy.get('#newPasswordRepeat').focus().type('iBurri3dMySe1f!')
      cy.get('#resetButton').click()

      cy.get('.confirmation').should('not.be.hidden')
      cy.expectChallengeSolved({ challenge: "Reset Morty's Password" })
    })
  })

  describe('as Uvogin', () => {
    it('should be able to reset password with his security answer', () => {
      cy.task<string>('GetFromConfig', 'application.domain').then(
        (appDomain: string) => {
          cy.get('#email').type(`uvogin@${appDomain}`)
        }
      )
      cy.wait('@securityQuestion')
      cy.get('#securityAnswer').should('not.be.disabled').focus().type('Jf3m-Cwz8-Qbn6-Hkr2')
      // Cypress recordings to properly fix behavior during test
      cy.get('#newPassword').focus().type('ora-ora > muda-muda')
      cy.get('#newPasswordRepeat').focus().type('ora-ora > muda-muda')
      cy.get('#resetButton').click()

      cy.get('.confirmation').should('not.be.hidden')
      cy.expectChallengeSolved({ challenge: "Reset Uvogin's Password" })
    })
  })
})
